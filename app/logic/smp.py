from app.db.sqlite import get_db, check_user_exists
from app.db.redis import get_redis, get_redis_list
from app.logic.data import delete_old_data
from base64 import b64encode
import json
import logging


redis_client = get_redis()


def initiate_new_smp(user_id: str, recipient_id: str, kem_public_key: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)

    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "kem_public_key": kem_public_key,
        "data_type": "smp"
    }))


def smp_step_processor(user_id: str, recipient_id: str, ciphertext_blob: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)

    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "ciphertext_blob": ciphertext_blob,
        "data_type": "smp"
    }))



def smp_failure_processor(user_id: str, recipient_id: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")

    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)

    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "failure": True,
        "data_type": "smp"
    }))
