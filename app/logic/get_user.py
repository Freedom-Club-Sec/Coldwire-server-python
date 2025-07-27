from app.db.sqlite import get_db, check_user_exists

def check_user(user_id: str) -> str:
    return check_user_exists(user_id)

