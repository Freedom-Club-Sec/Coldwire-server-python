from base64 import b64decode
from app.logic.config_parser import config
import secrets
import string
import ipaddress

def is_valid_domain_or_ip(s: str) -> bool:
    if not s or len(s) > 253:
        return False


    if ":" in s and not s.count(":") > 1:  # crude check: allow single-port case only
        host, port = s.rsplit(":", 1)
        if not port.isdigit() or not (0 < int(port) < 65536):
            return False
        s = host


    try:
        ip = ipaddress.ip_address(s)
        for net in config["BLACKLISTED_IP_NETWORKS"]:
            if ip in ipaddress.ip_network(net):
                return False
        return True
    except ValueError:
        pass

    s_lower = s.lower()
    if s_lower in config["BLACKLISTED_DOMAINS"]:
        return False

    labels = s.split(".")
    if len(labels) < 2:  
        return False

    for label in labels:
        if not (1 <= len(label) <= 63):
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isascii() and (ch.isalnum() or ch == "-")):
                return False

    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False

    return True


def valid_b64(s: str) -> bool:
    if not s.strip():
        return False

    try:
        b64decode(s, validate=True)
        return True
    except Exception:
        return False

def valid_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except:
        return False

def generate_user_id(length: int = 16) -> str:
    return ''.join(secrets.choice(string.digits) for _ in range(length))

