#!/usr/bin/env python3
"""module for session authenticating views
"""


import os
from typing import Tuple
from flask import abort, jsonify, request
from api.v1.app import auth
from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_auth_login() -> Tuple[str, int]:
    """post api/v1/auth_session/login
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400
    user = User.search({'email': email})
    if not user:
        return jsonify({"error": "no user found for this email"}), 404
    if not user[0].is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401
    session_id = auth.create_session(getattr(user[0], 'id'))
    response = jsonify(user[0].to_json())
    response.set_cookie(os.getenv("SESSION_NAME"), session_id)
    return response


@app_views.route(
    '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def session_auth_logout():
    """delete api/v1/auth_session/logout
    """
    is_destroyed = auth.destroy_session(request)
    if not is_destroyed:
        abort(404)
    return jsonify({}), 200
