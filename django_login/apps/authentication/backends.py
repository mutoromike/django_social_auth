import datetime

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

"""Configure JWT Here"""


secret_key = settings.SECRET_KEY


class Authentication(TokenAuthentication):

    @staticmethod
    def generate_jwt_token(user, refresh_token=False):
        """ method to generate token """

        token = jwt.encode({
            "username": user["username"],
            "refresh_token": refresh_token,
            "iat": datetime.datetime.utcnow(),
            'nbf': datetime.datetime.utcnow() + datetime.timedelta(minutes=-5),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
        }, secret_key)
        token = str(token, 'utf-8')
        return token

    def authenticate_credentials(self, key):

        try:
            payload = jwt.decode(key, secret_key)
            user = get_user_model().objects.get(username=payload["username"])

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed(
                'Token has expired please request for another'
            )
        return (user, payload)

    @staticmethod
    def decode_jwt_token(token):
        try:
            user_info = jwt.decode(token, secret_key)
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed(
                'Token has expired please request for another')
        return user_info
