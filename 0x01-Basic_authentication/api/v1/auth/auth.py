#!/usr/bin/env python3
""" Auth Class """
from flask import request
from typing import List, TypeVar
from re import search


class Auth:
    """ Auth CLass """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Auth Guard """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != '/':
            path += '/'
        return not any(search(p, path) for p in excluded_paths)

    def authorization_header(self, req: request = None) -> str:
        """ Auth Header """
        if req is None:
            return None
        return req.headers.get('Authorization', None)

        # if req
        #
        # return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current User """
        return None
