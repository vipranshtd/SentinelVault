
import os
import base64
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

def get_master_key():
    encoded_key = os.getenv("MASTER_KEY")

    if not encoded_key:
        raise RuntimeError("MASTER_KEY is missing from .env")

    try:
        key = base64.b64decode(encoded_key, validate=True)
    except Exception as exc:
        raise RuntimeError("Invalid MASTER_KEY encoding") from exc

    if len(key) != 32:
        raise RuntimeError("MASTER_KEY must be exactly 32 bytes")

    return key


def generate_data_key():
    return AESGCM.generate_key(bit_length=256)


def wrap_data_key(data_key, storage_id):
    master_key = get_master_key()
    nonce = secrets.token_bytes(12)

    wrapped_key = AESGCM(master_key).encrypt(
        nonce,
        data_key,
        storage_id.encode("utf-8")
    )

    return nonce, wrapped_key


def unwrap_data_key(nonce, wrapped_key, storage_id):
    master_key = get_master_key()

    return AESGCM(master_key).decrypt(
        nonce,
        wrapped_key,
        storage_id.encode("utf-8")
    )
