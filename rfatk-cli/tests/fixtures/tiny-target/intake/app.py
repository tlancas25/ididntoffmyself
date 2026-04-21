"""Tiny Flask notes-app for REDFORGE integration testing.

Starts a Flask server that lets authenticated users manage personal notes.
Auth is a dumb bearer-token lookup against the users table.
"""

from flask import Flask, jsonify, request

import db
import users

app = Flask(__name__)


def _current_user():
    """Resolve the caller's user row from the Authorization: Bearer <token> header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):].strip()
    return db.find_user_by_token(token)


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json() or {}
    email = body.get("email", "")
    password = body.get("password", "")
    # Looks up the user by email — see db.find_user_by_email().
    user = db.find_user_by_email(email)
    if not user or not db.check_password(user, password):
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": user["token"]})


app.register_blueprint(users.bp)


if __name__ == "__main__":
    db.init_db()
    app.run(host="0.0.0.0", port=8080)
