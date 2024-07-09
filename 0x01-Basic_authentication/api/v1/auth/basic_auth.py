#!/usr/bin/env python3
"""basic authentication module for api
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """basic authentication class
    """
    def extract_base64_authorization_header(
            self,
            authorization_headr: str) -> str:
        """extract base64 of the authorization header
        """
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field_match = re.fullmatch(pattern, authorization_header.strip())
            if field_match is not None:
                return field_match.group('token')
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_headr: str,
            ) -> str:
        """decode base64 of the authorization header
        """
        if type(base64_authorization_headr) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_headr,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_headr: str
            ) -> Tuple[str, str]:
        """extract the user credentials from decoded base64
        authorization headr
        """
        if type(decoded_base64_authorization_headr) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+'
            field_match = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """retrieves a user based on the
        user's authentication credentials
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """retrieve the user from the request
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)