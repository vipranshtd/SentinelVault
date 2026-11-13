
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app import app
from database.db_manager import get_db
from services.audit_service import log_event


with app.app_context():
    email = input("Enter the registered email to promote: ").strip().lower()

    db = get_db()

    user = db.execute(
        "SELECT user_id, username, email, role FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if user is None:
        print("No account found with that email.")

    elif user["role"] == "admin":
        print("This account is already an administrator.")

    else:
        confirmation = input(
            f"Promote {user['username']} to administrator? (yes/no): "
        ).strip().lower()

        if confirmation == "yes":
            db.execute(
                "UPDATE users SET role = 'admin' WHERE user_id = ?",
                (user["user_id"],)
            )
            db.commit()

            log_event(
                "ADMIN_ROLE_GRANTED",
                "SUCCESS",
                None,
                None,
                f"Administrator role granted to user ID {user['user_id']} through local provisioning"
            )

            print("Administrator role assigned successfully.")

        else:
            print("Operation cancelled.")
