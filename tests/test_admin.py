
from tests.conftest import create_user

PASSWORD = "StrongPassword123!"


def login(client, email):
    return client.post("/login", data={
        "email": email,
        "password": PASSWORD
    })


def test_normal_user_cannot_access_admin(app, client):
    create_user(app)

    login(client, "test@example.com")

    response = client.get("/admin/")

    assert response.status_code == 403


def test_admin_dashboard_access(app, client):
    create_user(
        app,
        email="admin@example.com",
        role="admin"
    )

    login(client, "admin@example.com")

    response = client.get("/admin/")

    assert response.status_code == 200


def test_normal_user_cannot_access_audit_logs(app, client):
    create_user(app)

    login(client, "test@example.com")

    response = client.get("/admin/audit")

    assert response.status_code == 403


def test_admin_can_access_audit_logs(app, client):
    create_user(
        app,
        email="admin@example.com",
        role="admin"
    )

    login(client, "admin@example.com")

    response = client.get("/admin/audit")

    assert response.status_code == 200
