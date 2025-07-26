from app.db.sqlite import get_db, check_user_exists
from app.db.redis import get_redis, get_redis_list
import json


redis_client = get_redis()

def check_new_pfs_messages(user_id: str) -> list:
    key = f"pfs:{user_id}"
    messages = get_redis_list(redis_client, key)
    redis_client.delete(key)
    return messages

def delete_old_pfs(target_id: str, sender_id: str) -> None:
    key = f"pfs:{target_id}"
    all_msgs = redis_client.lrange(key, 0, -1)
    keep = []

    for raw in all_msgs:
        msg = json.loads(raw)
        if not (msg.get("sender") == sender_id):
            keep.append(json.dumps(msg))

    pipe = redis_client.pipeline()
    pipe.delete(key)
    if keep:
        pipe.rpush(key, *keep)
    pipe.execute()


def ephemeral_keys_processor(user_id: str, recipient_id: str, kyber_publickey_hashchain: str, kyber_hashchain_signature: str, d5_public_key, d5_signature, pfs_type: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old PFS messages sent to the recipient by the user
    delete_old_pfs(recipient_id, user_id)

    key = f"pfs:{recipient_id}"

    payload = {
        "sender": user_id,
        "kyber_publickey_hashchain": kyber_publickey_hashchain,
        "kyber_hashchain_signature": kyber_hashchain_signature,
        "pfs_type": pfs_type,
        "data_type": "pfs"
    } 

    if d5_public_key and d5_signature:
        payload["d5_public_key"] = d5_public_key
        payload["d5_signature"] = d5_signature

    redis_client.rpush(key, json.dumps(payload))


