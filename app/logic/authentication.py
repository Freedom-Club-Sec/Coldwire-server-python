from app.db.sqlite import get_db
from app.db.redis import get_redis
from app.utils.helper_utils import generate_user_id
from app.utils.jwt import create_jwt_token
from base64 import b64encode
from app.core.constants import (
    CHALLENGE_LEN
)
import secrets
import sqlite3
import json


redis_client = get_redis()

def handle_authentication_jwt(public_key: bytes, user_id: str) -> (str, str):
    with get_db() as conn:
        cursor = conn.cursor()

        # If the user_id is empty, we keep generating user_ids and 
        # checking if they're duplicated or not. if we find one 
        # not already registered, that's the user's ID.

        if user_id == "": 
            while True:
                user_id = generate_user_id() 
                cursor.execute(f'SELECT 1 FROM users WHERE id = "{user_id}" LIMIT 1')
                exists = cursor.fetchone() is not None
                if exists:
                    continue

                break
        
            # Inserting public-key here is safe, because the SQL schema ensures public_key is unique for every user
            # if user tries to use another users public-key, this will raise an exception.
            cursor.execute("""INSERT INTO users (id, public_key) VALUES (?, ?)""", ( user_id, public_key, ))

            conn.commit()
        
        user_token = create_jwt_token({"id": user_id})


        return (user_id, user_token)


def handle_authentication_init(user_id: str, public_key: str) -> str:
    if public_key:
        return set_verification_challenge(user_id, public_key)

    with get_db() as conn:
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute("SELECT public_key FROM users WHERE id = ?", (user_id,))
            public_key = cursor.fetchone()
            if public_key is None:
                raise ValueError("User ID does not exist!")

            public_key = b64encode(public_key[0]).decode()

            return set_verification_challenge(user_id, public_key)

def set_verification_challenge(user_id: str, public_key: str) -> str:
    challenge = b64encode(secrets.token_bytes(CHALLENGE_LEN)).decode()
    redis_client.set(f"challenges:{challenge}", json.dumps([user_id, public_key]))
    return challenge

def get_challenge_data(challenge: str) -> (str, str):
    raw = redis_client.get(f"challenges:{challenge}")
    if raw is not None:
        redis_client.delete(f"challenges{challenge}")
        return json.loads(raw)

    raise ValueError("Challenge not found")


def check_id_public_key(user_id: str, public_key: bytes) -> bool:
    if not user_id.isdigit():
        return False

    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT public_key FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            if row[0] == public_key:
               return True

        return False

