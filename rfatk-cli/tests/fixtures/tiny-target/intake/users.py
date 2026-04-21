"""User / notes routes.

Endpoints:
  GET  /users/<user_id>/notes  — list a user's notes
  POST /users/<user_id>/notes  — create a note for that user
"""

from flask import Blueprint, jsonify, request

import db

bp = Blueprint("users", __name__)


@bp.route("/users/<user_id>/notes", methods=["GET"])
def list_user_notes(user_id):
    """Return the notes owned by <user_id>.

    Called by the React frontend after login. The frontend always supplies
    the current user's own id, so in practice only owners hit this — but
    the server itself does not enforce that. Any authenticated user can
    read any other user's notes by substituting their user_id in the URL.
    """
    # TODO(authn): we check that the caller has *some* valid token, but we
    # don't confirm the token's owning user matches <user_id>. This is a
    # textbook IDOR — horizontal privilege escalation between users.
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401
    token = auth[len("Bearer "):].strip()
    if not db.find_user_by_token(token):
        return jsonify({"error": "unauthorized"}), 401

    notes = db.list_notes(user_id)
    return jsonify(notes)


@bp.route("/users/<user_id>/notes", methods=["POST"])
def create_user_note(user_id):
    """Create a note for <user_id>. Same IDOR issue — no ownership check."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401
    token = auth[len("Bearer "):].strip()
    if not db.find_user_by_token(token):
        return jsonify({"error": "unauthorized"}), 401

    body = (request.get_json() or {}).get("body", "")
    # writes a note as user_id regardless of who the bearer belongs to.
    # (DB insert happens via a raw helper not shown here in this MVP.)
    return jsonify({"ok": True, "user_id": user_id, "body": body}), 201
