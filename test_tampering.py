
from pathlib import Path
from database.db_manager import get_db
from core.encryption import decrypt_file
from flask import Flask
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

with app.app_context():
    db = get_db()

    record = db.execute(
        "SELECT * FROM files LIMIT 1"
    ).fetchone()

    if record is None:
        print("No uploaded files found.")
        raise SystemExit

    storage_path = (
        Path(app.config["STORAGE_PATH"])
        / f"{record['storage_id']}.svault"
    )

    encrypted_data = storage_path.read_bytes()

    tampered_data = bytearray(encrypted_data)
    tampered_data[0] ^= 1

    print("Testing original encrypted file...")

    try:
        decrypt_file(
            encrypted_data,
            record["nonce"],
            record["key_nonce"],
            record["wrapped_key"],
            record["storage_id"],
            record["original_sha256"]
        )
        print("Original file: DECRYPTION SUCCESSFUL")
    except Exception as e:
        print("Original file: FAILED", type(e).__name__)

    print("\nTesting modified encrypted file...")

    try:
        decrypt_file(
            bytes(tampered_data),
            record["nonce"],
            record["key_nonce"],
            record["wrapped_key"],
            record["storage_id"],
            record["original_sha256"]
        )
        print("WARNING: Tampering was not detected!")
    except Exception as e:
        print("SUCCESS: Tampering detected:", type(e).__name__)
