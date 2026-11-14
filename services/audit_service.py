
from database.db_manager import get_db


def _clean_log_value(value, max_length):
    if value is None:
        return None

    value = str(value)
    value = value.replace("\r", " ").replace("\n", " ")
    return value[:max_length]


def log_event(event_type, outcome, actor_id=None, file_id=None, details=None):
    db = get_db()

    event_type = _clean_log_value(event_type, 100)
    outcome = _clean_log_value(outcome, 30)
    details = _clean_log_value(details, 500)

    if not event_type or not outcome:
        raise ValueError("Event type and outcome are required.")

    db.execute(
        """
        INSERT INTO audit_events
        (actor_id, event_type, outcome, file_id, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (actor_id, event_type, outcome, file_id, details)
    )

    db.commit()
