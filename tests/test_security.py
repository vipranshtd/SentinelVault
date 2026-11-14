
import pytest
from cryptography.exceptions import InvalidTag

def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json["status"] == "running"

def test_security_headers(client):
    response = client.get("/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Cache-Control"] == "no-store"

def test_encryption_decryption():
    from core.encryption import encrypt_file, decrypt_file

    original = b"SentinelVault security test"

    encrypted = encrypt_file(original, "test-storage-id")

    decrypted = decrypt_file(
        encrypted["encrypted_data"],
        encrypted["nonce"],
        encrypted["key_nonce"],
        encrypted["wrapped_key"],
        "test-storage-id",
        encrypted["original_sha256"]
    )

    assert decrypted == original

def test_encryption_tampering_detection():
    from core.encryption import encrypt_file, decrypt_file

    original = b"SentinelVault encryption test"

    encrypted = encrypt_file(original, "test-storage-id")

    tampered = bytearray(encrypted["encrypted_data"])
    tampered[0] ^= 1

    with pytest.raises(InvalidTag):
        decrypt_file(
            bytes(tampered),
            encrypted["nonce"],
            encrypted["key_nonce"],
            encrypted["wrapped_key"],
            "test-storage-id",
            encrypted["original_sha256"]
        )