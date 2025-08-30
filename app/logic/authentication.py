from app.db.sqlite import get_db
from app.db.redis import get_redis, get_redis_list
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

def handle_authentication(public_key: bytes, user_id: str = None) -> (str, str):
    with get_db() as conn:
        cursor = conn.cursor()

        # If the user_id is empty, means the user wants to register.
        # We keep generating user_ids and checking if they're duplicated or not
        # if we find one not already registered, we create a JWT token with it inside.

        if user_id == "": 
            while True:
                user_id = generate_user_id() 
                cursor.execute(f'SELECT 1 FROM users WHERE id = "{user_id}" LIMIT 1')
                exists = cursor.fetchone() is not None
                if exists:
                    continue

                break

        # As the user_id is already sanitization checked in the routes function, we can safely bundle it in.
        user_token = create_jwt_token({"id": user_id})
        
        try:
            cursor.execute("""
                INSERT INTO users (id, public_key)
                VALUES (?, ?)
            """,
                (
                    user_id, 
                    public_key,
                )
            )

            conn.commit()
            print(f"User ({user_id}) inserted successfully.")
        except sqlite3.IntegrityError:
            print(f"User ({user_id}) authenticated successfully.")

        return (user_id, user_token)


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

