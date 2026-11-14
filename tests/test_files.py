
import io

from database.db_manager import get_db
from tests.conftest import create_user


PASSWORD = "StrongPassword123!"
FILE_CONTENT = b"SentinelVault security test"


def login(client, email):
    return client.post("/login", data={
        "email": email,
        "password": PASSWORD
    })


def upload_text_file(client):
    return client.post(
        "/files/upload",
        data={
            "file": (
                io.BytesIO(FILE_CONTENT),
                "test.txt"
            )
        },
        content_type="multipart/form-data",
        follow_redirects=True
    )


def get_uploaded_file(app):
    with app.app_context():
        record = get_db().execute(
            "SELECT * FROM files ORDER BY file_id DESC LIMIT 1"
        ).fetchone()

        return dict(record)


def test_file_upload_and_download(app, client):
    create_user(app)
    login(client, "test@example.com")

    upload_text_file(client)

    record = get_uploaded_file(app)
    file_id = record["file_id"]

    response = client.get(f"/files/download/{file_id}")

    assert response.status_code == 200
    assert response.data == FILE_CONTENT


def test_file_integrity_verification(app, client):
    create_user(app)
    login(client, "test@example.com")

    upload_text_file(client)

    record = get_uploaded_file(app)

    response = client.post(
        f"/files/verify/{record['file_id']}",
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Integrity verified" in response.data


def test_tampered_file_fails_integrity_check(app, client):
    create_user(app)
    login(client, "test@example.com")

    upload_text_file(client)

    record = get_uploaded_file(app)

    encrypted_path = (
        app.config["STORAGE_PATH"]
        / f"{record['storage_id']}.svault"
    )

    encrypted_data = bytearray(encrypted_path.read_bytes())
    encrypted_data[0] ^= 1
    encrypted_path.write_bytes(encrypted_data)

    response = client.post(
        f"/files/verify/{record['file_id']}",
        follow_redirects=True
    )

    assert response.status_code == 200
    assert b"Integrity verification failed" in response.data


def test_user_cannot_access_another_users_file(app, client):
    create_user(
        app,
        username="firstuser",
        email="first@example.com"
    )

    login(client, "first@example.com")
    upload_text_file(client)

    record = get_uploaded_file(app)
    file_id = record["file_id"]

    client.post("/logout")

    create_user(
        app,
        username="seconduser",
        email="second@example.com"
    )

    login(client, "second@example.com")

    response = client.get(f"/files/download/{file_id}")

    assert response.status_code != 200
    assert FILE_CONTENT not in response.data


def test_file_deletion(app, client):
    create_user(app)
    login(client, "test@example.com")

    upload_text_file(client)

    record = get_uploaded_file(app)
    file_id = record["file_id"]

    response = client.post(
        f"/files/delete/{file_id}",
        follow_redirects=True
    )

    assert response.status_code == 200

    with app.app_context():
        deleted_record = get_db().execute(
            "SELECT * FROM files WHERE file_id = ?",
            (file_id,)
        ).fetchone()

        assert deleted_record is None


def test_deleted_file_cannot_be_downloaded(app, client):
    create_user(app)
    login(client, "test@example.com")

    upload_text_file(client)

    record = get_uploaded_file(app)
    file_id = record["file_id"]

    client.post(
        f"/files/delete/{file_id}",
        follow_redirects=True
    )

    response = client.get(f"/files/download/{file_id}")

    assert response.status_code != 200
    assert FILE_CONTENT not in response.data
