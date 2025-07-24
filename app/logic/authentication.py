from app.db.sqlite import get_db
from app.utils.helper_utils import generate_user_id
from app.utils.jwt import create_jwt_token
import sqlite3

def handle_authentication(public_key: bytes, user_id: str = None) -> (str, str):
    with get_db() as conn:
        cursor = conn.cursor()

        if user_id == "": 
            while True:
                user_id = generate_user_id() 
                cursor.execute(f'SELECT 1 FROM users WHERE id = "{user_id}" LIMIT 1')
                exists = cursor.fetchone() is not None
                if exists:
                    print("Generated User ID is duplicated, retrying...")
                    continue

                break

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

