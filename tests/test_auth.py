
from tests.conftest import create_user


def register(client, username="newuser",
             email="new@example.com",
             password="StrongPassword123!"):
    return client.post("/register", data={
        "username": username,
        "email": email,
        "password": password
    })


def login(client, email="new@example.com",
          password="StrongPassword123!"):
    return client.post("/login", data={
        "email": email,
        "password": password
    })


def test_user_registration(client):
    response = register(client)
    assert response.status_code == 302


def test_duplicate_email_registration(client):
    register(client)

    response = register(
        client,
        username="anotheruser",
        email="new@example.com"
    )

    assert response.status_code == 200


def test_successful_login(client):
    register(client)

    response = login(client)

    assert response.status_code == 302

def test_invalid_password(client):
    register(client)

    login(client, password="WrongPassword123!")

    with client.session_transaction() as session:
        assert "_user_id" not in session

def test_account_lockout(app, client):
    create_user(app)

    for _ in range(5):
        login(client, password="WrongPassword123!")

    response = login(client)

    assert response.status_code == 302

    with client.session_transaction() as session:
        assert "_user_id" not in session

def test_dashboard_requires_login(client):
    response = client.get("/dashboard")

    assert response.status_code == 302


def test_logout(app, client):
    create_user(app)

    login(client)

    response = client.post("/logout")

    assert response.status_code == 302

    response = client.get("/dashboard")

    assert response.status_code == 302
