import os
import time
import struct
import logging
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_KYBER768_K = 3
_Q = 3329                                         
_EK_BYTE_LEN = 384 * _KYBER768_K + 32            

def _byte_decode_12(b: bytes) -> list[int]:
    coeffs = []
    for i in range(0, len(b) - 1, 3):           
        b0, b1, b2 = b[i], b[i + 1], b[i + 2]
        coeffs.append(b0 | ((b1 & 0x0F) << 8))
        coeffs.append((b1 >> 4) | (b2 << 4))
    return coeffs


def _byte_encode_12(coeffs: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(coeffs) - 1, 2):
        a, b_ = coeffs[i] & 0xFFF, coeffs[i + 1] & 0xFFF
        out.append(a & 0xFF)
        out.append((a >> 8) | ((b_ & 0x0F) << 4))
        out.append(b_ >> 4)
    return bytes(out)


def validate_encapsulation_key(ek: bytes) -> None:
    if not isinstance(ek, (bytes, bytearray)):
        raise ValueError(
            f"FIPS 203 §7.2 Check 1 FAIL: encapsulation key must be bytes, "
            f"got {type(ek).__name__}"
        )
    if len(ek) != _EK_BYTE_LEN:
        raise ValueError(
            f"FIPS 203 §7.2 Check 1 FAIL: expected {_EK_BYTE_LEN} bytes "
            f"(384·k+32, k=3), got {len(ek)}"
        )

    t = bytes(ek[: 384 * _KYBER768_K])           
    coefficients = _byte_decode_12(t)

    for idx, c in enumerate(coefficients):
        if c >= _Q:
            raise ValueError(
                f"FIPS 203 §7.2 Check 2 FAIL: coefficient[{idx}] = {c} ≥ q={_Q}"
            )

    re_encoded = _byte_encode_12(coefficients)
    if re_encoded != t:
        raise ValueError(
            "FIPS 203 §7.2 Check 2 FAIL: ByteEncode₁₂(ByteDecode₁₂(ek[0:384k])) "
            "≠ ek[0:384k]; key is malformed."
        )

    logger.debug("FIPS 203 §7.2: both input checks passed for encapsulation key.")

def _zero(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0

class PostQuantumCrypto:
    KEM_ALGO = "Kyber768"
    SIG_ALGO = "ML-DSA-44"          
    ALGORITHM_NAME = "Kyber768+ML-DSA-44+AES-256-GCM"

    def __init__(self) -> None:
        with oqs.KeyEncapsulation(self.KEM_ALGO) as kem:
            self.kem_public_key: bytes = kem.generate_keypair()
            self.kem_secret_key: bytes = kem.export_secret_key()

        with oqs.Signature(self.SIG_ALGO) as sig:
            self.sig_public_key: bytes = sig.generate_keypair()
            self.sig_secret_key: bytes = sig.export_secret_key()

        validate_encapsulation_key(self.kem_public_key)
        logger.info("PostQuantumCrypto initialised; KEM public key validated (FIPS 203 §7.2).")

    def encrypt(self, plaintext: bytes) -> dict:
        start = time.perf_counter()
        validate_encapsulation_key(self.kem_public_key)

        shared_secret_ba: bytearray | None = None
        aes_key_ba: bytearray | None = None

        try:
            with oqs.KeyEncapsulation(self.KEM_ALGO) as kem:
                kem_ciphertext, shared_secret_raw = kem.encap_secret(self.kem_public_key)

            shared_secret_ba = bytearray(shared_secret_raw)
            aes_key_ba = bytearray(shared_secret_ba[:32])

            nonce = os.urandom(12)
            ciphertext = AESGCM(bytes(aes_key_ba)).encrypt(nonce, plaintext, None)

            with oqs.Signature(self.SIG_ALGO, self.sig_secret_key) as sig:
                signature = sig.sign(ciphertext)

            elapsed_ms = (time.perf_counter() - start) * 1000
            return {
                "algorithm": self.ALGORITHM_NAME,
                "ciphertext": ciphertext,
                "kem_ciphertext": kem_ciphertext,
                "nonce": nonce,
                "signature": signature,
                "encrypt_ms": round(elapsed_ms, 3),
            }
        finally:
            if aes_key_ba is not None:
                _zero(aes_key_ba)
            if shared_secret_ba is not None:
                _zero(shared_secret_ba)

    def decrypt(self, pkg: dict) -> dict:
        start = time.perf_counter()

        shared_secret_ba: bytearray | None = None
        aes_key_ba: bytearray | None = None

        try:
            with oqs.Signature(self.SIG_ALGO) as sig:
                valid = sig.verify(pkg["ciphertext"], pkg["signature"], self.sig_public_key)
            if not valid:
                raise ValueError("ML-DSA-44 signature verification failed — ciphertext tampered.")

            with oqs.KeyEncapsulation(self.KEM_ALGO, self.kem_secret_key) as kem:
                shared_secret_raw = kem.decap_secret(pkg["kem_ciphertext"])

            shared_secret_ba = bytearray(shared_secret_raw)
            aes_key_ba = bytearray(shared_secret_ba[:32])

            plaintext = AESGCM(bytes(aes_key_ba)).decrypt(pkg["nonce"], pkg["ciphertext"], None)
            elapsed_ms = (time.perf_counter() - start) * 1000
            return {"plaintext": plaintext, "decrypt_ms": round(elapsed_ms, 3)}
        finally:
            if aes_key_ba is not None:
                _zero(aes_key_ba)
            if shared_secret_ba is not None:
                _zero(shared_secret_ba)

    def get_public_key_info(self) -> dict:
        return {
            "kem_public_key": self.kem_public_key,
            "sig_public_key": self.sig_public_key,
            "kem_algo": self.KEM_ALGO,
            "sig_algo": self.SIG_ALGO,
        }
