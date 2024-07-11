#!/usr/bin/env python3
"""model for session expiration
"""


import os
from datetime import datetime as dt, timedelta
from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """add session expiration to the authentication mechanism
    """

    def __init__(self):
        """constructor for session expire class
        """
        super().__init__()
        self.session_duration = int(os.environ.get("SESSION_DURATION", 0))

    def create_session(self, user_id: int) -> str:
        """create a new session for a user
        """
        sessn_id = super().create_session(user_id)
        if sessn_id is None:
            return None
        self.user_id_by_session_id[sessn_id] = {
            'user_id': user_id,
            'created_at': dt.now()
        }
        return sessn_id

    def user_id_for_session_id(self, session_id: str) -> int:
        """get the user id associated with a session id
        """
        if session_id is None:
            return None
        if session_id not in self.user_id_by_session_id:
            return None
        session_dict = self.user_id_by_session_id.get(session_id)
        if session_dict is None:
            return None
        if self.session_duration <= 0:
            return session_dict.get("user_id")
        created_at = session_dict.get('created_at')
        if created_at is None:
            return None
        now = dt.now()
        if created_at + timedelta(seconds=self.session_duration) < now:
            return None
        expires_at = session_dict["created_at"] + \
            timedelta(seconds=self.session_duration)
        if expires_at < dt.now():
            return None
        return session_dict.get("user_id", None)
