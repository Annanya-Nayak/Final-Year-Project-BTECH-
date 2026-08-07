import os
import time
import logging

import oqs
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.classical import ClassicalCrypto
from crypto.post_quantum import PostQuantumCrypto, validate_encapsulation_key, _zero

logger = logging.getLogger(__name__)

_HKDF_INFO = b"PQC-AI-Hybrid-v1"
_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def _derive_key_hkdf(classical_secret: bytes, kyber_secret: bytes) -> bytes:
    ikm = classical_secret + kyber_secret          
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,                                  
        info=_HKDF_INFO,
    )
    return hkdf.derive(ikm)


class HybridCrypto:
    ALGORITHM_NAME = "RSA-2048+Kyber768+ML-DSA-44+AES-256-GCM (HKDF)"

    def __init__(self) -> None:
        self._classical = ClassicalCrypto()
        self._pqc = PostQuantumCrypto()

    def encrypt(self, plaintext: bytes) -> dict:
        start = time.perf_counter()

        validate_encapsulation_key(self._pqc.kem_public_key)

        classical_secret_ba: bytearray | None = None
        kyber_secret_ba: bytearray | None = None
        final_key_ba: bytearray | None = None

        try:
            classical_secret_raw = os.urandom(32)
            classical_secret_ba = bytearray(classical_secret_raw)

            with oqs.KeyEncapsulation(self._pqc.KEM_ALGO) as kem:
                kem_ct, kyber_secret_raw = kem.encap_secret(self._pqc.kem_public_key)
            kyber_secret_ba = bytearray(kyber_secret_raw)

            final_key = _derive_key_hkdf(
                bytes(classical_secret_ba),
                bytes(kyber_secret_ba[:32]),
            )
            final_key_ba = bytearray(final_key)

            nonce = os.urandom(12)
            ciphertext = AESGCM(bytes(final_key_ba)).encrypt(nonce, plaintext, None)

            rsa_enc_key = self._classical.public_key.encrypt(
                bytes(classical_secret_ba), _OAEP_PADDING
            )

            with oqs.Signature(self._pqc.SIG_ALGO, self._pqc.sig_secret_key) as sig:
                signature = sig.sign(ciphertext)

            elapsed_ms = (time.perf_counter() - start) * 1000
            return {
                "algorithm": self.ALGORITHM_NAME,
                "ciphertext": ciphertext,
                "rsa_enc_key": rsa_enc_key,
                "kem_ct": kem_ct,
                "nonce": nonce,
                "signature": signature,
                "encrypt_ms": round(elapsed_ms, 3),
            }
        finally:
            for buf in (classical_secret_ba, kyber_secret_ba, final_key_ba):
                if buf is not None:
                    _zero(buf)

    def decrypt(self, pkg: dict) -> dict:
        start = time.perf_counter()

        classical_secret_ba: bytearray | None = None
        kyber_secret_ba: bytearray | None = None
        final_key_ba: bytearray | None = None

        try:
            with oqs.Signature(self._pqc.SIG_ALGO) as sig:
                valid = sig.verify(
                    pkg["ciphertext"], pkg["signature"], self._pqc.sig_public_key
                )
            if not valid:
                raise ValueError("ML-DSA-44 signature verification failed — ciphertext tampered.")

            classical_secret_raw = self._classical.private_key.decrypt(
                pkg["rsa_enc_key"], _OAEP_PADDING
            )
            classical_secret_ba = bytearray(classical_secret_raw)

            with oqs.KeyEncapsulation(self._pqc.KEM_ALGO, self._pqc.kem_secret_key) as kem:
                kyber_secret_raw = kem.decap_secret(pkg["kem_ct"])
            kyber_secret_ba = bytearray(kyber_secret_raw)

            final_key = _derive_key_hkdf(
                bytes(classical_secret_ba),
                bytes(kyber_secret_ba[:32]),
            )
            final_key_ba = bytearray(final_key)

            plaintext = AESGCM(bytes(final_key_ba)).decrypt(
                pkg["nonce"], pkg["ciphertext"], None
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            return {"plaintext": plaintext, "decrypt_ms": round(elapsed_ms, 3)}
        finally:
            for buf in (classical_secret_ba, kyber_secret_ba, final_key_ba):
                if buf is not None:
                    _zero(buf)

    def get_public_key_info(self) -> dict:
        return {
            "rsa_public_key_pem": self._classical.public_key_pem(),
            "kem_public_key": self._pqc.kem_public_key,
            "sig_public_key": self._pqc.sig_public_key,
            "kem_algo": self._pqc.KEM_ALGO,
            "sig_algo": self._pqc.SIG_ALGO,
            "kdf": "HKDF-SHA256 (SP 800-56C Rev.2 §4)",
        }
