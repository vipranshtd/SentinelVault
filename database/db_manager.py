
import sqlite3
from pathlib import Path

from flask import current_app, g


def get_db():
    if "db" not in g:
        db_path = current_app.config["DATABASE_PATH"]

        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


def close_db(exception=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db(database_path):
    database_path = Path(database_path)
    database_path.parent.mkdir(parents=True, exist_ok=True)

    schema_path = Path(__file__).with_name("schema.sql")
    schema = schema_path.read_text(encoding="utf-8")

    connection = sqlite3.connect(database_path)

    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(schema)

        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(files)"
            ).fetchall()
        }

        for column in ("nonce", "key_nonce", "wrapped_key"):
            if column not in columns:
                connection.execute(
                    f"ALTER TABLE files ADD COLUMN {column} BLOB"
                )

        connection.commit()

    finally:
        connection.close()


def init_app(app):
    app.teardown_appcontext(close_db)
