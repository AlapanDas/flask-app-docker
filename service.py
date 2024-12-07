import bcrypt
import os
from dotenv import load_dotenv
load_dotenv()

def hashpassword(password: str) -> str:
    """
    Hashes a password using bcrypt with a custom salt from the environment.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        str: The hashed password.
    """
   
    salt_env = os.getenv("SALT")

    if not salt_env:
        raise ValueError("SALT environment variable is not set in .env file.")

    salt = salt_env.encode('utf-8')
    password_bytes = password.encode('utf-8')

    hashed_password = bcrypt.hashpw(password_bytes, salt)

    return hashed_password.decode('utf-8')

