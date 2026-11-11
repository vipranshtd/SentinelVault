
from core.encryption import encrypt_file, decrypt_file
from cryptography.exceptions import InvalidTag


original = b"SentinelVault confidential test document"

storage_id = "test-file-001"

# Encrypt
result = encrypt_file(original, storage_id)

print("Encryption successful")
print("Encrypted data:", result["encrypted_data"][:30])

# Decrypt
recovered = decrypt_file(
    result["encrypted_data"],
    result["nonce"],
    result["key_nonce"],
    result["wrapped_key"],
    storage_id,
    result["original_sha256"]
)

print("Decryption successful")
print("Original matches recovered:", original == recovered)

# Tampering test
tampered = bytearray(result["encrypted_data"])
tampered[0] ^= 1

try:
    decrypt_file(
        bytes(tampered),
        result["nonce"],
        result["key_nonce"],
        result["wrapped_key"],
        storage_id,
        result["original_sha256"]
    )
    print("ERROR: Tampering was not detected")

except InvalidTag:
    print("SUCCESS: Tampering detected!")
