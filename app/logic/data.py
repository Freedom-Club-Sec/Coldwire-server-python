from app.db.sqlite import get_db
from app.db.redis import get_redis, get_redis_list
import json
import logging


redis_client = get_redis()

def check_new_data(user_id: str) -> list:
    messages = get_redis_list(redis_client, user_id)
    redis_client.delete(user_id)
    return messages

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


