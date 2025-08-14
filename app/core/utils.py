# app/core/utils.py
from datetime import datetime
import uuid
import hashlib

def ts() -> str:
    return datetime.utcnow().isoformat() + "Z"

def mk_id(prefix: str = "nad") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()