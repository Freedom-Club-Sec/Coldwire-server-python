from fastapi import Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import os

JWT_SECRET = os.environ.get("JWT_SECRET")
ALGORITHM = "HS512"

# We don't expire JWTs as Coldwire doesn't support multiple devices.
# And we don't implement expiration for JWTs to prevent login and activity timestamp logging -
# incase the server wasn't malicious and was compromised later.
# Additionally, the secret should be rotated every month.
# Should be fine for now, but we might want add some sort of expiration mechanism that doesn't depend on time

def create_jwt_token(data: dict) -> str:
    return jwt.encode(data, JWT_SECRET, algorithm=ALGORITHM)

def decode_jwt_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")


def verify_jwt_token(creds: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS512"])
        return payload
    except jwt.PyJWTError:
        raise JSONException(status_code=401, content={"status": "failure", "error": "Invalid token"})


def check_jwt_exists() -> None:
    JWT_SECRET = os.environ.get("JWT_SECRET")

    if not JWT_SECRET:
        print("""[ERROR] JWT_SECRET not set.

    Run this command to generate a JWT secret and save it in .env:

echo -n "JWT_SECRET=" > .env && openssl rand -base64 64 | tr -d '\\n' >> .env
    """)

        os._exit(1)
