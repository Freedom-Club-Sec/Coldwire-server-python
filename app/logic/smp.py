from app.db.sqlite import get_db, check_user_exists
from app.db.redis import get_redis, get_redis_list
from app.logic.data import delete_old_data
from base64 import b64encode
import json
import logging


redis_client = get_redis()


# The reason we have each step in its own function is to ensure a client can't manually set the data
# and to actually have code with no surpises that is easily to audit - even if its a bit repetitive,
# as the SMP implementation is a very important part of Coldwire's security.

def initiate_new_smp(user_id: str, recipient_id: str, nonce: str, signing_public_key: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)

    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "step": 1,
        "nonce": nonce,
        "signing_public_key": signing_public_key,
        "data_type": "smp"
    }))


def smp_step_2_processor(user_id: str, recipient_id: str, nonce: str, signing_public_key: str, question_public_key: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)

    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "step": 2,
        "nonce": nonce,
        "signing_public_key": signing_public_key,
        "question_public_key": question_public_key,
        "data_type": "smp"
    }))


def smp_step_3_processor(user_id: str, recipient_id: str, question_pads_ciphertext: str, question_ciphertext: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)

    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "step": 3,
        "question_pads_ciphertext": question_pads_ciphertext,
        "question_ciphertext": question_ciphertext,
        "data_type": "smp"
    }))



def smp_step_4_processor(user_id: str, recipient_id: str, proof: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)

    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "step": 4,
        "proof": proof,
        "data_type": "smp"
    }))



def smp_step_5_processor(user_id: str, recipient_id: str, proof: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)


    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "step": 5,
        "proof": proof,
        "data_type": "smp"
    }))


def smp_step_6_processor(user_id: str, recipient_id: str, proof: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")
  
    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)


    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "step": 6,
        "proof": proof,
        "data_type": "smp"
    }))



def smp_failure_processor(user_id: str, recipient_id: str) -> None:
    if not check_user_exists(recipient_id):
        raise ValueError("Recipient_id does not exist")

    # Delete any old SMP messages sent to the recipient by the user
    delete_old_data(recipient_id, "smp", user_id)

    redis_client.rpush(recipient_id, json.dumps({
        "sender": user_id,
        "step": -1,
        "data_type": "smp"
    }))
