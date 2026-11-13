
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from database.db_manager import get_db
from core.authorization import admin_required
from services.audit_service import log_event

admin = Blueprint("admin", __name__, url_prefix="/admin")


@admin.route("/")
@login_required
@admin_required
def dashboard():
    db = get_db()

    total_users = db.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    active_users = db.execute(
        "SELECT COUNT(*) FROM users WHERE is_active = 1"
    ).fetchone()[0]

    total_files = db.execute(
        "SELECT COUNT(*) FROM files"
    ).fetchone()[0]

    total_events = db.execute(
        "SELECT COUNT(*) FROM audit_events"
    ).fetchone()[0]

    recent_events = db.execute(
        """
        SELECT audit_events.*, users.username
        FROM audit_events
        LEFT JOIN users
        ON audit_events.actor_id = users.user_id
        ORDER BY audit_events.created_at DESC
        LIMIT 15
        """
    ).fetchall()

    users = db.execute(
        """
        SELECT user_id, username, email, role, is_active, created_at
        FROM users
        ORDER BY created_at DESC
        """
    ).fetchall()

    return render_template(
        "admin.html",
        total_users=total_users,
        active_users=active_users,
        total_files=total_files,
        total_events=total_events,
        recent_events=recent_events,
        users=users
    )


@admin.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id):
    db = get_db()

    target = db.execute(
        "SELECT * FROM users WHERE user_id = ?",
        (user_id,)
    ).fetchone()

    if target is None:
        flash("User not found.", "error")
        return redirect(url_for("admin.dashboard"))

    if int(current_user.id) == user_id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin.dashboard"))

    new_status = 0 if target["is_active"] else 1

    if target["role"] == "admin" and new_status == 0:
        active_admins = db.execute(
            """
            SELECT COUNT(*) FROM users
            WHERE role = 'admin' AND is_active = 1
            """
        ).fetchone()[0]

        if active_admins <= 1:
            flash("The last active administrator cannot be deactivated.", "error")
            return redirect(url_for("admin.dashboard"))

    db.execute(
        "UPDATE users SET is_active = ? WHERE user_id = ?",
        (new_status, user_id)
    )
    db.commit()

    action = "ACTIVATED" if new_status else "DEACTIVATED"

    try:
        log_event(
            "ADMIN_USER_STATUS_CHANGE",
            "SUCCESS",
            int(current_user.id),
            None,
            f"Administrator {action.lower()} account ID {user_id}"
        )
    except Exception:
        from flask import current_app
        current_app.logger.exception("Failed to record administrative action")

    flash(f"User account {action.lower()} successfully.", "success")
    return redirect(url_for("admin.dashboard"))
