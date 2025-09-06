from app.db.sqlite import check_user_exists
from app.db.redis import get_redis
from app.logic.config_parser import config
from app.logic.federation_utils import send_to_server
from app.utils.helper_utils import is_valid_domain_or_ip
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

def data_processor(user_id: str, recipient: str, blob: bytes) -> None:
    if recipient.isdigit():
        if len(recipient) != 16:
            raise ValueError("Invalid recipient ID")
     
        if not check_user_exists(recipient):
            raise ValueError("Recipient_id does not exist")

        user_id = user_id.encode("utf-8")
        
        # \0 is seperator. User_ids cannot have a seperator.
        
        if COLDWIRE_DATA_SEP in user_id:
            raise ValueError("User ID cannot have null byte!")

        payload = user_id + COLDWIRE_DATA_SEP + blob
        length_prefix = len(payload).to_bytes(COLDWIRE_LEN_OFFSET, "big")

        payload = length_prefix + payload

        redis_client.rpush(recipient, payload)

    # Max DNS length is 253, 16 for recipient user ID, and 1 for `@`
    elif len(recipient) > 253 + 16 + 1:
        raise ValueError("Invalid recipient ID or address")
    else:
        recipient_split = recipient.split("@", 1)
        if len(recipient_split) != 2:
            raise ValueError("Invalid recipient ID or address")

        if (not recipient_split[0].isdigit()) or (len(recipient_split[0]) != 16):
            raise ValueError("Invalid recipient ID")

        if not config["federation_enabled"]:
            raise ValueError("Federation support is disabled")

        recipient_id = recipient_split[0]
    
        # Note: the user could put our IP instead of our domain, which would allow him to bypass this check. Not big deal, but could be a vector for reflected DDoS.
        # We recommend putting server behind a CDN (like Cloudflare), and firewall blocking packets except from CDN's IPs to reduce DDoS abuse.
        url = recipient_split[1].strip().lower()
        if url == config["YOUR_DOMAIN_OR_IP"].lower():
            raise ValueError("You cannot send data reflectly to our same server.")

        if not is_valid_domain_or_ip(url):
            raise ValueError("Invalid server domain and or IP")

        send_to_server(url, user_id, recipient_id, blob)
 

    
