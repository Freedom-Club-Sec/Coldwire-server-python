from app.db.sqlite import get_db, check_user_exists
from app.db.redis import get_redis, get_redis_list
from base64 import b64encode
import json
import logging


redis_client = get_redis()

def check_new_smp_messages(user_id: str) -> list:
    key = f"smp:{user_id}"
    messages = get_redis_list(redis_client, key)
    redis_client.delete(key)
    return messages

def delete_old_smps(target_id: str, sender_id: str) -> None:
    key = f"smp:{target_id}"
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




# The reason we have each step in its own function is to ensure a client can't manually set the data
# and to actually have code with no surpises that is easily to audit - even if its ugly,
# as the SMP implementation is a very important part of Coldwire's security.
# The server is given 0 trust, but it is assumed the server won't try to crash the client
# As of now, the server could denial-of-service the client if it wants to, and that's fine.
# Such crashes are not result of classical bugs i.e. stack overflows, logic bugs, and whatnot. 
# Rather it is caused by trusting the server will (usually) provide data in its correct type and no missing data.
# The client code does some sanity checking, but it does not attempt to convert insane data to sane 
# If a server tries giving invalid or incomplete data anywhere, a Python exception is raised in a thread on the client,
# and all other threads will crash on purpose as a failsafe mechanism.
# If you are dealing with a malicious server that is actively crashing you, simply use another.


def initiate_new_smp(user_id: str, recipient_id: str, question: str, nonce: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_smps(recipient_id, user_id)

    key = f"smp:{recipient_id}"

    redis_client.rpush(key, json.dumps({
        "sender": user_id,
        "step": 1,
        "question": question,
        "nonce": nonce
    }))


def smp_step_2_processor(user_id: str, recipient_id: str, proof: str, nonce: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_smps(recipient_id, user_id)

    key = f"smp:{recipient_id}"

    redis_client.rpush(key, json.dumps({
        "sender": user_id,
        "step": 2,
        "proof": proof,
        "nonce": nonce
    }))


def smp_step_3_processor(user_id: str, recipient_id: str, proof: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_smps(recipient_id, user_id)

    key = f"smp:{recipient_id}"

    redis_client.rpush(key, json.dumps({
        "sender": user_id,
        "step": 3,
        "proof": proof,
    }))



def smp_failure_processor(user_id: str, recipient_id: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")

    # Delete any old SMP messages sent to the recipient by the user
    delete_old_smps(recipient_id, user_id)

    key = f"smp:{recipient_id}"

    redis_client.rpush(key, json.dumps({
        "sender": user_id,
        "step": -1,
    }))
