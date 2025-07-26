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

def otp_batch_processor(user_id: str, recipient_id: str, json_payload: str, payload_signature: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")

    try:
        json_payload_decoded = json.loads(json_payload)
        if (not "ciphertext_blob" in json_payload_decoded) or (not "replay_protection_number" in json_payload_decoded):
            raise Exception()

        # Kyber1024 ciphertext is always 1568, and since our default One-Time-Pad size is 10 kilobytes
        # We can be confident that the decoded ciphertext_blob size must match 501760 bytes
        # 10240 / 32 = 320
        # 320 x 1568 = 501760
        if (not valid_b64(json_payload_decoded["ciphertext_blob"])) or len(b64decode(json_payload_decoded["ciphertext_blob"])) != 501760:
            raise Exception()

        if not (isinstance(json_payload_decoded["replay_protection_number"], int)):
            raise Exception()

    except:
        raise ValueError("Inner JSON payload is malformed")

    key = f"messages:{recipient_id}"

    payload = {
        "sender": user_id,
        "msg_type": "new_otp_batch",
        "json_payload": json_payload,
        "payload_signature": payload_signature,
        "data_type": "message"
    } 

    redis_client.rpush(key, json.dumps(payload))


def otp_message_processor(user_id: str, recipient_id: str, json_payload: str, payload_signature: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")

    try:
        json_payload_decoded = json.loads(json_payload)
        if (not "message_encrypted" in json_payload_decoded) or (not "replay_protection_number" in json_payload_decoded):
            raise Exception()

        # Maxmimum message_encrypted length is maximum OTP batch length which is 10 kilobytes (10240 bytes)
        if (not valid_b64(json_payload_decoded["message_encrypted"])) or len(b64decode(json_payload_decoded["message_encrypted"])) > 10240:
            raise Exception()

        if not (isinstance(json_payload_decoded["replay_protection_number"], int)):
            raise Exception()

    except:
        raise ValueError("Inner JSON payload is malformed")

    key = f"messages:{recipient_id}"

    payload = {
        "sender": user_id,
        "msg_type": "new_message",
        "json_payload": json_payload,
        "payload_signature": payload_signature,
        "data_type": "message"
    } 

    redis_client.rpush(key, json.dumps(payload))


