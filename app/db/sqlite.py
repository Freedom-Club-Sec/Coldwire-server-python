import sqlite3
from contextlib import contextmanager
from pathlib import Path
from app.core.crypto import (
        generate_sign_keys
)

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
        print("Initializing database for first time...")
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS servers (
                    url TEXT PRIMARY KEY,
                    public_key BLOB UNIQUE NOT NULL,
                    refetch_date TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS our_keys (
                    id INTEGER PRIMARY KEY,
                    private_key BLOB UNIQUE NOT NULL,
                    public_key BLOB UNIQUE NOT NULL
                );

            """)
            conn.commit()

            private_key, public_key = generate_sign_keys()
            cursor.execute(
                "INSERT INTO our_keys (private_key, public_key) VALUES (?, ?)",
                (private_key, public_key)
            )


            conn.commit()



def check_user_exists(user_id: str) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
        exists = cursor.fetchone() is not None
        if not exists:
            return False

        return True


