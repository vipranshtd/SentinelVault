
from datetime import datetime, timedelta, timezone
import sqlite3

from flask import Blueprint, render_template, request, redirect, url_for, flash , session
from flask_login import login_user, logout_user, current_user, login_required
from argon2 import PasswordHasher

from database.db_manager import get_db
from core.user import User
from core.authentication import hash_password, verify_password
from services.audit_service import log_event

auth = Blueprint("auth", __name__)

MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 10
password_hasher = PasswordHasher()


@auth.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth.register"))

        if len(username) > 50 or len(email) > 254:
            flash("Input exceeds the allowed length.", "error")
            return redirect(url_for("auth.register"))

        if len(password) < 12 or len(password) > 128:
            flash("Password must contain 12–128 characters.", "error")
            return redirect(url_for("auth.register"))

        if any(char.isspace() for char in password):
            flash("Password must not contain whitespace.", "error")
            return redirect(url_for("auth.register"))

        db = get_db()

        try:
            cursor = db.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, hash_password(password))
            )
            db.commit()

            user_id = cursor.lastrowid
            log_event("REGISTRATION", "SUCCESS", user_id)

            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("auth.login"))

        except sqlite3.IntegrityError:
            db.rollback()
            flash("Unable to create account with these details.", "error")

    return render_template("register.html")


@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user is None:
            log_event("LOGIN", "FAILED")
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth.login"))

        now = datetime.now(timezone.utc)

        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])

            if locked_until > now:
                flash("Account temporarily locked. Try again later.", "error")
                return redirect(url_for("auth.login"))

        if not user["is_active"]:
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth.login"))

        if not verify_password(user["password_hash"], password):
            attempts = user["failed_login_attempts"] + 1
            locked_until = None

            if attempts >= MAX_ATTEMPTS:
                locked_until = (
                    now + timedelta(minutes=LOCKOUT_MINUTES)
                ).isoformat()
                attempts = 0

            db.execute(
                """
                UPDATE users
                SET failed_login_attempts = ?, locked_until = ?
                WHERE user_id = ?
                """,
                (attempts, locked_until, user["user_id"])
            )
            db.commit()

            log_event("LOGIN", "FAILED", user["user_id"])
            flash("Invalid email or password.", "error")
            return redirect(url_for("auth.login"))

        db.execute(
            """
            UPDATE users
            SET failed_login_attempts = 0, locked_until = NULL
            WHERE user_id = ?
            """,
            (user["user_id"],)
        )
        db.commit()

        account = User(
            user["user_id"],
            user["username"],
            user["email"],
            user["role"],
        )
        session.permanent = True
        login_user(account, remember=False, fresh=True)
        log_event("LOGIN", "SUCCESS", user["user_id"])

        flash("Welcome back!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@auth.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("LOGOUT", "SUCCESS", int(current_user.id))
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
