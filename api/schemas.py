from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

class SensitivityLevel(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"

class CryptoMode(str, Enum):
    CLASSICAL    = "classical"
    HYBRID       = "hybrid"
    POST_QUANTUM = "post_quantum"

class PredictRequest(BaseModel):
    text:        str            = Field(..., min_length=1, max_length=512)
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM
    request_id:  Optional[str] = None

class PredictResponse(BaseModel):
    label:            str
    score:            float
    inference_time_ms: float
    total_time_ms:    float
    crypto_mode:      CryptoMode
    policy_score:     float
    policy_reasoning: str
    request_id:       Optional[str]

class KeysResponse(BaseModel):
    
    mode:               CryptoMode
    kem_public_key_hex: Optional[str] = None   # None for classical-only
    sig_public_key_hex: Optional[str] = None
    rsa_public_key_pem: Optional[str] = None   # None for PQ-only
    kem_algo:           Optional[str] = None
    sig_algo:           Optional[str] = None

class EncryptedPredictRequest(BaseModel):
    
    sensitivity:        SensitivityLevel = SensitivityLevel.MEDIUM
    request_id:         Optional[str]    = None
    kem_ciphertext_hex: Optional[str]    = None
    rsa_enc_key_hex:    Optional[str]    = None
    nonce_hex:          str              = Field(..., min_length=24, max_length=24)
    ciphertext_hex:     str              = Field(..., min_length=2)

class EncryptedPredictResponse(BaseModel):
    
    response_nonce_hex:       str
    response_ciphertext_hex:  str
    response_kem_ct_hex:      Optional[str] = None
    response_rsa_enc_key_hex: Optional[str] = None
    crypto_mode:              CryptoMode
    policy_score:             float
    policy_reasoning:         str
    total_time_ms:            float
    request_id:               Optional[str]

class HealthResponse(BaseModel):
    status:          str
    model_loaded:    bool
    cpu_percent:     float
    memory_percent:  float
    uptime_seconds:  float

class MetricsResponse(BaseModel):
    total_requests:         int
    avg_latency_ms:         float
    current_cpu_percent:    float
    algorithm_distribution: dict
    q_table_updates:        dict    
    replay_buffer_sizes:    dict     