from app.db.sqlite import get_db, check_user_exists
from app.db.redis import get_redis
from app.core.constants import (
        COLDWIRE_LEN_OFFSET,
        COLDWIRE_DATA_SEP
)


redis_client = get_redis()


def get_redis_list(client, key: str) -> list:
    data = b""
    while True:
        raw = client.lpop(key)
        if raw is None:
            break

        data += raw

    return data

def check_new_data(user_id: str) -> bytes:
    return get_redis_list(redis_client, user_id)

def data_processor(user_id: str, recipient_id: str, blob: bytes) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")

    user_id = user_id.encode("utf-8")
    
    # \0 is seperator. User_ids cannot have a seperator.
    
    if COLDWIRE_DATA_SEP in user_id:
        raise ValueError("User ID cannot have null byte!")

    payload = user_id + COLDWIRE_DATA_SEP + blob
    length_prefix = len(payload).to_bytes(COLDWIRE_LEN_OFFSET, "big")

    payload = length_prefix + payload

    redis_client.rpush(recipient_id, payload)


"""
def delete_old_data(target_id: str, data_type: str, sender_id: str) -> None:
    all_msgs = redis_client.lrange(target_id, 0, -1)
    keep = []

    for raw in all_msgs:
        msg = json.loads(raw)
        if (msg.get("sender") != sender_id) and msg.get("data_type") != data_type:
            keep.append(json.dumps(msg))

    pipe = redis_client.pipeline()
    pipe.delete(target_id)
    if keep:
        pipe.rpush(target_id, *keep)
    pipe.execute()

"""
