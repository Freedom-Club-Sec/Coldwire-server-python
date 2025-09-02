from app.db.sqlite import get_db, check_user_exists
from app.db.redis import get_redis, get_redis_list
import json
import logging

redis_client = get_redis()

def message_processor(user_id: str, recipient_id: str, ciphertext_blob: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")

    payload = {
        "sender": user_id,
        "ciphertext_blob": ciphertext_blob,
        "data_type": "message"
    } 

    redis_client.rpush(recipient_id, json.dumps(payload))


