#!/usr/bin/env python3
""" Class that inherits from Auth """
from api.v1.auth.auth import Auth
from typing import TypeVar
from flask import request
from base64 import b64decode
from models.user import User


class BasicAuth(Auth):
    """ Basic Auth class """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ Base64 Authorization Header """
        if (authorization_header is None or type(authorization_header)
                is not str):
            return None
        if authorization_header[:6] != "Basic ":
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """ Decode Base64 Authorization Header """
        if (not base64_authorization_header or
                type(base64_authorization_header) is not str):
            return None
        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """ Extract User Credentials """
        if (not decoded_base64_authorization_header or
                not isinstance(decoded_base64_authorization_header, str)):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        email_pwd = decoded_base64_authorization_header.split(':')
        return (email_pwd[0], ':'.join(email_pwd[1]))

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ User Object from Credentials """
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        try:
            user = User()
            u = user.search({'email': user_email})
            if not u:
                return None
            if not u[0].is_valid_password(user_pwd):
                return None
            return u[0]
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current User """
        auth_header = (
            self.authorization_header(request))
        base64_auth_header = (
            self.extract_base64_authorization_header(auth_header))
        decoded_auth_header = (
            self.decode_base64_authorization_header(base64_auth_header))
        user_email, user_pwd = (
            self.extract_user_credentials(decoded_auth_header))
        return self.user_object_from_credentials(user_email, user_pwd)
