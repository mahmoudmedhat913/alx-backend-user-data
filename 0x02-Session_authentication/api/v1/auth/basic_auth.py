#!/usr/bin/env python3
"""basic authentication module for api
"""
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """basic authentication class
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """extract base64 of the authorization header
        """
        if authorization_header is None or not \
                isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split("Basic ")[1].strip()

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """decode base64 of the authorization header
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded = base64.b64decode(
                base64_authorization_header,
                validate=True,
            )
            return decoded.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self, decoded_header: str) -> Tuple[str, str]:
        """extract the user credentials from decoded base64
        authorization headr
        """
        if decoded_header is None or not isinstance(decoded_header, str):
            return None, None
        try:
            email, password = decoded_header.split(':', 1)
        except ValueError:
            return None, None
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """retrieves a user based on the
        user's authentication credentials
        """
        if not all(map(lambda x: isinstance(x, str), (user_email, user_pwd))):
            return None
        try:
            user = User.search(attributes={'email': user_email})
        except Exception:
            return None
        if not user:
            return None
        user = user[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """retrieve the user from the request
        """
        auth_header = self.authorization_header(request)
        b64_auth_header = self.extract_base64_authorization_header(auth_header)
        dec_header = self.decode_base64_authorization_header(b64_auth_header)
        user_email, user_pwd = self.extract_user_credentials(dec_header)
        return self.user_object_from_credentials(user_email, user_pwd)
