
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")

    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY is missing. Configure it in .env")

    DATABASE_PATH = BASE_DIR / "instance" / "sentinelvault.db"

    STORAGE_PATH = BASE_DIR / "storage" / "encrypted"

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False

    PERMANENT_SESSION_LIFETIME = 1800

    WTF_CSRF_ENABLED = True
