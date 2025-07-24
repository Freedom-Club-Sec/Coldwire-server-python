import redis
import json


redis_client = redis.Redis(
    host='localhost',
    port=6379,
    db=0,
    decode_responses=False 
)

def get_redis():
    return redis_client


# Returns a json list, from a key's value list
def get_redis_list(client, key: str) -> list:
    messages = []

    raw_messages = client.lrange(key, 0, -1)
    for raw in raw_messages:
        messages.append(json.loads(raw))

    return messages

