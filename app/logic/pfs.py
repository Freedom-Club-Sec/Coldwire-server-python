from app.db.sqlite import get_db, check_user_exists
from app.db.redis import get_redis, get_redis_list
from app.logic.data import delete_old_data
import json


redis_client = get_redis()


def ephemeral_keys_processor(user_id: str, recipient_id: str, ciphertext_blob: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old PFS messages sent to the recipient by the user
    # NOTE: Idk if this is even needed anymore, but i will keep it cuz nothing is breaking lol
    delete_old_data(recipient_id, "pfs", user_id)

    payload = {
        "sender": user_id,
        "ciphertext_blob": ciphertext_blob,
        "data_type": "pfs",
    } 

    redis_client.rpush(recipient_id, json.dumps(payload))


