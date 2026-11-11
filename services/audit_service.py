
from database.db_manager import get_db


def log_event(event_type, outcome, actor_id=None, file_id=None, details=None):
    db = get_db()

    db.execute(
        """
        INSERT INTO audit_events
        (actor_id, event_type, outcome, file_id, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (actor_id, event_type, outcome, file_id, details)
    )

    db.commit()
