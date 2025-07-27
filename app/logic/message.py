from app.db.sqlite import get_db, check_user_exists
from app.db.redis import get_redis, get_redis_list
from app.utils.helper_utils import valid_b64
from base64 import b64decode
import json
import logging

redis_client = get_redis()

def check_new_messages(user_id: str) -> list:
    key = f"messages:{user_id}"
    messages = get_redis_list(redis_client, key)
    redis_client.delete(key)
    return messages

def otp_batch_processor(user_id: str, recipient_id: str, otp_hashchain_ciphertext: str, otp_hashchain_signature: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")


    key = f"messages:{recipient_id}"

    payload = {
        "sender": user_id,
        "msg_type": "new_otp_batch",
        "otp_hashchain_ciphertext": otp_hashchain_ciphertext,
        "otp_hashchain_signature": otp_hashchain_signature,
        "data_type": "message"
    } 

    redis_client.rpush(key, json.dumps(payload))


def otp_message_processor(user_id: str, recipient_id: str, message_encrypted: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")

    key = f"messages:{recipient_id}"

    payload = {
        "sender": user_id,
        "msg_type": "new_message",
        "message_encrypted": message_encrypted,
        "data_type": "message"
    } 

    redis_client.rpush(key, json.dumps(payload))


