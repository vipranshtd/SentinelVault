
from pathlib import Path

from flask import Flask, render_template, redirect, url_for
from flask_login import LoginManager, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from database.db_manager import init_db, init_app as init_db_app
from database.db_manager import get_db
from core.user import User
from routes.auth_routes import auth


app = Flask(__name__)
app.config.from_object(Config)


# Flask-Login
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE user_id = ? AND is_active = 1",
        (user_id,)
    ).fetchone()

    if user is None:
        return None

    return User(
    user["user_id"],
    user["username"],
    user["email"],
    user["role"]
)


# Security components
csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[]
)
limiter.init_app(app)


# Directories and database
Path(app.config["DATABASE_PATH"]).parent.mkdir(
    parents=True, exist_ok=True
)

Path(app.config["STORAGE_PATH"]).mkdir(
    parents=True, exist_ok=True
)

init_db(app.config["DATABASE_PATH"])
init_db_app(app)


# Register authentication routes
app.register_blueprint(auth)

# Apply login rate limiting
app.view_functions["auth.login"] = limiter.limit("10 per minute")(
    app.view_functions["auth.login"]
)


# Security headers
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


# Homepage
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return render_template("index.html")


# Protected dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# Health check
@app.route("/health")
def health():
    return {"status": "running"}


if __name__ == "__main__":
    app.run(debug=True)
