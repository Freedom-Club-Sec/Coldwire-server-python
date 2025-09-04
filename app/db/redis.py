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


