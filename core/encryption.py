
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.key_manager import (
    generate_data_key,
    wrap_data_key,
    unwrap_data_key
)


def encrypt_file(file_data, storage_id):
    data_key = generate_data_key()
    nonce = secrets.token_bytes(12)

    aad = storage_id.encode("utf-8")

    encrypted_data = AESGCM(data_key).encrypt(
        nonce,
        file_data,
        aad
    )

    key_nonce, wrapped_key = wrap_data_key(
        data_key,
        storage_id
    )

    file_hash = hashlib.sha256(file_data).hexdigest()

    return {
        "encrypted_data": encrypted_data,
        "nonce": nonce,
        "key_nonce": key_nonce,
        "wrapped_key": wrapped_key,
        "original_sha256": file_hash
    }


def decrypt_file(encrypted_data, nonce, key_nonce,
                 wrapped_key, storage_id, original_sha256):

    aad = storage_id.encode("utf-8")

    data_key = unwrap_data_key(
        key_nonce,
        wrapped_key,
        storage_id
    )

    decrypted_data = AESGCM(data_key).decrypt(
        nonce,
        encrypted_data,
        aad
    )

    actual_hash = hashlib.sha256(decrypted_data).hexdigest()

    if actual_hash != original_sha256:
        raise ValueError("File integrity verification failed")

    return decrypted_data
