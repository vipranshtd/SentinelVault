
import pytest

import database.db_manager as db_manager

# Prevent the real database from being initialized during app import.
original_init_db = db_manager.init_db
db_manager.init_db = lambda database_path: None

import app as app_module

# Restore the original database initialization function.
db_manager.init_db = original_init_db


@pytest.fixture
def app(tmp_path):
    test_database = tmp_path / "test_sentinelvault.db"
    test_storage = tmp_path / "encrypted"

    test_storage.mkdir(parents=True)

    application = app_module.app

    application.config.update(
        TESTING=True,
        DATABASE_PATH=test_database,
        STORAGE_PATH=test_storage,
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=False
    )

    db_manager.init_db(test_database)

    yield application


@pytest.fixture
def client(app):
    return app.test_client()


def create_user(
    app,
    username="testuser",
    email="test@example.com",
    password="StrongPassword123!",
    role="user"
):
    from core.authentication import hash_password

    with app.app_context():
        db = db_manager.get_db()

        cursor = db.execute(
            """
            INSERT INTO users
            (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            (username, email, hash_password(password), role)
        )

        db.commit()

        return cursor.lastrowid
