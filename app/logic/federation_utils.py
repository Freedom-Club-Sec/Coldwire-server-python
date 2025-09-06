from app.core.requests import (
        http_request
)
from app.core.crypto import (
        verify_signature,
        create_signature
)
from app.core.constants import (
        ML_DSA_87_NAME,
        ML_DSA_87_PK_LEN,
        ML_DSA_87_SIGN_LEN,
        COLDWIRE_DATA_SEP,
        COLDWIRE_LEN_OFFSET,
        CHALLENGE_LEN
)

from app.logic.config_parser import config
from app.db.redis import get_redis
from app.db.sqlite import get_db, check_user_exists
from app.utils.helper_utils import is_valid_domain_or_ip
from base64 import b64encode, b64decode
import json

redis_client = get_redis()

def fetch_and_save_server_info(url: str) -> bytes:
    response = json.loads(http_request(f"http://{url}/federation/info", "GET").decode())

    public_key   = b64decode(response["public_key"])
    signature    = b64decode(response["signature"])
    refetch_date = response["refetch_date"]

    if len(public_key) != ML_DSA_87_PK_LEN:
        raise ValueError(f"Public key size ({len(public_key)}) is not equal ML-DSA-87 public key size ({ML_DSA_87_PK_LEN})")
    
    if len(signature) != ML_DSA_87_SIGN_LEN:
        raise ValueError(f"Signature size ({len(signature)}) is not equal ML-DSA-87 signature size ({ML_DSA_87_SIGN_LEN})")

    # URL must not contain any protocol prefixes (i.e. HTTP:// or HTTPS://).
    is_valid = verify_signature(ML_DSA_87_NAME, url.encode("utf-8") + refetch_date.encode("utf-8"), signature, public_key)
    if not is_valid:
        raise ValueError("Signature is invalid!")

    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO servers (url, public_key, refetch_date) VALUES (?, ?, ?)",
                (url, public_key, refetch_date)
            )
            conn.commit()

        except Exception:
            cursor.execute(
                "UPDATE servers SET public_key = ?, refetch_date = ? WHERE url = ?",
                (public_key, refetch_date, url)
            )
            conn.commit()


    return public_key


def federation_processor(url: str, sender: str, recipient: str, blob: bytes) -> None:
    if len(blob) <= ML_DSA_87_SIGN_LEN:
        raise ValueError("Malformed signature + blob")

    if not is_valid_domain_or_ip(url):
        raise ValueError("Malformed URL")

    if not check_user_exists(recipient):
        raise ValueError("Recipient_id does not exist")


    public_key = get_server_public_key(url)
    if public_key is None:
        public_key = fetch_and_save_server_info(url)

    signature = blob[:ML_DSA_87_SIGN_LEN]
    blob = blob[ML_DSA_87_SIGN_LEN:]

    is_valid = verify_signature(
            ML_DSA_87_NAME,
            config["YOUR_DOMAIN_OR_IP"].encode("utf-8") + recipient.encode("utf-8") + sender.encode("utf-8") + blob,
            signature, 
            public_key
    )

    if not is_valid:
        raise ValueError("Signature is invalid!")


    sender_with_url = sender + "@" + url
    sender_with_url = sender_with_url.encode("utf-8")

    if COLDWIRE_DATA_SEP in sender_with_url:
        raise ValueError("Sender ID cannot have null byte!")

    payload = sender_with_url + COLDWIRE_DATA_SEP + blob
    length_prefix = len(payload).to_bytes(COLDWIRE_LEN_OFFSET, "big")

    payload = length_prefix + payload

    redis_client.rpush(recipient, payload)




    
def get_federation_info() -> dict:
    public_key, private_key = get_our_keys()
    refetch_date = "testing"

    signature = create_signature(ML_DSA_87_NAME, config["YOUR_DOMAIN_OR_IP"].encode("utf-8") + refetch_date.encode("utf-8"), private_key)

    return {
            "public_key": b64encode(public_key).decode(),
            "refetch_date": refetch_date,
            "signature": b64encode(signature).decode()
        }

def get_our_keys() -> tuple[bytes, bytes]:
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT public_key, private_key FROM our_keys")
        return cursor.fetchone()


def get_server_public_key(url: str) -> bytes:
    with get_db() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT public_key FROM servers WHERE url = ?", (url,))
        public_key = cursor.fetchone()
        if public_key is None:
            return None
        else:
            return public_key[0]


def send_to_server(url: str, sender: str, recipient: str, blob: bytes):
    public_key, private_key = get_our_keys()

    signature = create_signature(ML_DSA_87_NAME, url.encode("utf-8") + recipient.encode("utf-8") + sender.encode("utf-8") + blob, private_key)

    http_request(f"http://{url}/federation/send", "POST", metadata = {
                "recipient": recipient,
                "sender": sender,
                "url": config["YOUR_DOMAIN_OR_IP"]
            },
            blob = signature + blob
        )
