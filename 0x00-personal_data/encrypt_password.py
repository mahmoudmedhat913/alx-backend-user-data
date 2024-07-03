#!/usr/bin/env python3
"""a module for encrypting passwords"""
import bcrypt


def hash_password(password: str) -> bytes:
    """hashes a password using random salt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """check if a hashed password was formed"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
