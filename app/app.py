import os
import sqlite3
import logging
from flask import Flask, request, jsonify, g

# --- Config ------------------------------------------------------------------
# NOTE: debug is intentionally env-driven. A security pipeline should flag
# running this with FLASK_DEBUG=1 in a non-dev environment.
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-key-change-me")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["DEBUG"] = DEBUG

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("soc-app")

DB_PATH = os.environ.get("DB_PATH", "users.db")


@app.after_request
def add_security_headers(response):
    # Apply to successful responses and application-generated errors alike.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    return response


# --- DB helpers --------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
        """
    )
    # Seed data (plaintext on purpose — pipeline should flag this)
    seed = [
        (1, "alice", "password123", "admin"),
        (2, "bob", "hunter2", "user"),
        (3, "carol", "letmein", "user"),
    ]
    for row in seed:
        try:
            conn.execute(
                "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
                row,
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()


# --- Routes ------------------------------------------------------------------
@app.route("/")
def index():
    return jsonify(
        {
            "service": "soc-test-app",
            "version": "0.1.0",
            "endpoints": ["/", "/health", "/users/<id>", "/login"],
        }
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/users/<user_id>")
def get_user(user_id):
    """
    Deliberately uses string concatenation instead of parameter binding.
    This creates a SQLi surface the pipeline should detect.
    """
    db = get_db()
    query = "SELECT id, username, role FROM users WHERE id = ?"
    log.info("Executing query: %s with id=%s", query, user_id)
    try:
        row = db.execute(query, (user_id,)).fetchone()
    except sqlite3.Error as e:
        # Verbose error surfaced to the client — also a finding.
        return jsonify({"error": str(e), "query": query}), 500

    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    db = get_db()
    # Parameterized (safe) — contrast with /users/<id>.
    row = db.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()

    log.info("Login attempt user=%s success=%s", username, row is not None)

    if row is None:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"message": "login ok", "user": dict(row)})


# --- Entrypoint --------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    # Bind to 0.0.0.0 so the pipeline can reach it in containers.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=DEBUG)
