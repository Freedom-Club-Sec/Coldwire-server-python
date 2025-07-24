from app.db.sqlite import get_db
from app.utils.helper_utils import generate_user_id
from app.utils.jwt import create_jwt_token
from base64 import b64encode
import sqlite3

def get_public_key(user_id: str) -> str:
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT public_key FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return b64encode(row[0]).decode()

        return "" 

