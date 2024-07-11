#!/usr/bin/env python3
"""authenticate module
"""
import os
from flask import request
from typing import List, TypeVar


class Auth:
    """authentication class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """method to check if auth is required
        """
        if not path:
            return True
        if not excluded_paths:
            return True
        path = path.rstrip("/")
        for excluded_path in excluded_paths:
            if excluded_path.endswith("*") and \
                    path.startswith(excluded_path[:-1]):
                return False
            elif path == excluded_path.rstrip("/"):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """method to get authorization header
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """method to get user from request"""
        return None

    def session_cookie(self, request=None) -> str:
        """retrieve session cookie from a request"""
        if request is not None:
            cookie_name = os.getenv('SESSION_NAME')
            return request.cookies.get(cookie_name)
