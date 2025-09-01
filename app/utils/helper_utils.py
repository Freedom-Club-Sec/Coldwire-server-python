from base64 import b64decode, b64encode
import secrets
import string


def valid_b64(s: str) -> bool:
    if not s.strip():
        return False

    try:
        b64decode(s, validate=True)
        return True
    except Exception:
        return False

def valid_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except:
        return False

def generate_user_id(length: int = 16) -> str:
    return ''.join(secrets.choice(string.digits) for _ in range(length))

