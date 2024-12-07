import jwt
import datetime
from dotenv import load_dotenv
import os
load_dotenv()


ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET", "default_access_secret")

def generate_access_token(data, expires_in=15):
    """
    Generates an access token with a short expiration time.
    Args:
        data (dict): The payload data for the token.
        expires_in (int): Expiration time in minutes.
    Returns:
        str: The generated access token.
    """
    payload = {
        **data,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_in),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, ACCESS_TOKEN_SECRET, algorithm="HS256")

def generate_refresh_token(data, expires_in=1440):
    """
    Generates a refresh token with a longer expiration time.
    Args:
        data (dict): The payload data for the token.
        expires_in (int): Expiration time in minutes.
    Returns:
        str: The generated refresh token.
    """
    payload = {
        **data,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_in),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, ACCESS_TOKEN_SECRET, algorithm="HS256")


def validate_token(token, is_refresh=False):
    """
    Validates a token and checks its expiration.
    Args:
        token (str): The token to validate.
        secret (str): Optional. The secret key to decode the token.
        is_refresh (bool): Whether the token is a refresh token.
    Returns:
        dict: The decoded payload if valid.
    Raises:
        jwt.ExpiredSignatureError: If the token is expired.
        jwt.InvalidTokenError: If the token is invalid.
    """
    secret = ACCESS_TOKEN_SECRET
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError(
            "Refresh token expired. Please log in again." if is_refresh else "Access token expired."
        )
    except jwt.InvalidTokenError:
        raise jwt.InvalidTokenError("Invalid token.")

def renew_access_token(refresh_token):
    """
    Renews the access token using a valid refresh token.
    Args:
        refresh_token (str): The refresh token to validate and use.
    Returns:
        str: The new access token.
    """

    try:
        # Validate the refresh token
        payload = validate_token(refresh_token, is_refresh=True)
        # Generate a new access token
        access_token = generate_access_token(payload)
        return access_token
    except jwt.ExpiredSignatureError:
        return "Refresh token expired. Please log in again."
    except jwt.InvalidTokenError:
        return "Invalid refresh token."
