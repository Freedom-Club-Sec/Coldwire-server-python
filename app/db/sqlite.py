import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path("database.db")

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()



def init_db():
    if not DB_PATH.exists():
        print("Initializing database...")
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL UNIQUE
                );
            """)
            conn.commit()

def check_user_exists(user_id: str) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
        exists = cursor.fetchone() is not None
        if not exists:
            return False

        return True


