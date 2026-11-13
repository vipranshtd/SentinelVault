
import os
import uuid

from pathlib import Path
from werkzeug.utils import secure_filename
from flask import current_app

from core.encryption import encrypt_file, decrypt_file
from database.db_manager import get_db
from services.audit_service import log_event

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "doc", "docx",
    "png", "jpg", "jpeg", "csv", "xlsx"
}

def upload_file(uploaded_file, user_id):
    original_filename = secure_filename(uploaded_file.filename or "")

    if not original_filename or "." not in original_filename:
        raise ValueError("Invalid filename.")

    extension = original_filename.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("This file type is not allowed.")

    file_data = uploaded_file.read()

    if not file_data:
        raise ValueError("Empty files cannot be uploaded.")

    if len(file_data) > current_app.config["MAX_CONTENT_LENGTH"]:
        raise ValueError("File exceeds the 16 MB limit.")

    storage_id = uuid.uuid4().hex
    encrypted = encrypt_file(file_data, storage_id)

    storage_dir = Path(current_app.config["STORAGE_PATH"])
    storage_path = storage_dir / f"{storage_id}.svault"
    temporary_path = storage_dir / f".{storage_id}.tmp"

    try:
        # Write ciphertext to a temporary file first.
        with open(temporary_path, "xb") as output:
            output.write(encrypted["encrypted_data"])
            output.flush()
            os.fsync(output.fileno())

        # Atomically move completed ciphertext into storage.
        os.replace(temporary_path, storage_path)

        db = get_db()

        try:
            cursor = db.execute(
                """
                INSERT INTO files (
                    owner_id,
                    display_filename,
                    storage_id,
                    encrypted_size,
                    original_size,
                    encryption_algorithm,
                    encryption_version,
                    original_sha256,
                    nonce,
                    key_nonce,
                    wrapped_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    original_filename,
                    storage_id,
                    len(encrypted["encrypted_data"]),
                    len(file_data),
                    "AES-256-GCM",
                    1,
                    encrypted["original_sha256"],
                    encrypted["nonce"],
                    encrypted["key_nonce"],
                    encrypted["wrapped_key"]
                )
            )

            file_id = cursor.lastrowid
            db.commit()

        except Exception:
            db.rollback()
            raise

        try:
            log_event(
                "FILE_UPLOAD_ENCRYPT",
                "SUCCESS",
                user_id,
                file_id,
                "File encrypted and stored successfully"
            )
        except Exception:
            current_app.logger.exception("Failed to record upload event")

        return file_id

    except Exception:
        temporary_path.unlink(missing_ok=True)
        storage_path.unlink(missing_ok=True)
        raise

def download_file(file_id, user_id):
    db = get_db()

    record = db.execute(
        """
        SELECT * FROM files
        WHERE file_id = ? AND owner_id = ?
        """,
        (file_id, user_id)
    ).fetchone()

    if record is None:
        return None

    storage_path = (
        Path(current_app.config["STORAGE_PATH"])
        / f"{record['storage_id']}.svault"
    )

    if not storage_path.is_file():
        raise FileNotFoundError("Encrypted file is missing.")

    encrypted_data = storage_path.read_bytes()

    decrypted_data = decrypt_file(
        encrypted_data,
        record["nonce"],
        record["key_nonce"],
        record["wrapped_key"],
        record["storage_id"],
        record["original_sha256"]
    )

    try:
        log_event(
            "FILE_DOWNLOAD_DECRYPT",
            "SUCCESS",
            user_id,
            file_id,
            "File decrypted and downloaded"
        )
    except Exception:
        current_app.logger.exception("Failed to record download event")

    return record["display_filename"], decrypted_data

def delete_file(file_id, user_id):
    db = get_db()

    record = db.execute(
        """
        SELECT * FROM files
        WHERE file_id = ? AND owner_id = ?
        """,
        (file_id, user_id)
    ).fetchone()

    if record is None:
        return False

    storage_path = (
        Path(current_app.config["STORAGE_PATH"])
        / f"{record['storage_id']}.svault"
    )

    if not storage_path.is_file():
        raise FileNotFoundError("Encrypted file is missing.")

    quarantine_path = storage_path.with_suffix(".deleting")

    os.replace(storage_path, quarantine_path)

    try:
        db.execute(
            "DELETE FROM files WHERE file_id = ? AND owner_id = ?",
            (file_id, user_id)
        )
        db.commit()

    except Exception:
        db.rollback()
        os.replace(quarantine_path, storage_path)
        raise

    quarantine_path.unlink(missing_ok=True)

    try:
        log_event(
            "FILE_DELETE",
            "SUCCESS",
            user_id,
            None,
            "Protected file deleted"
        )
    except Exception:
        current_app.logger.exception("Failed to record deletion event")

    return True