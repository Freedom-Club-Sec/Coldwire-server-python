from urllib import request, error
from app.core.crypto import (
    sha3_512
)
import urllib
import json
import logging
import string
import secrets


logger = logging.getLogger("uvicorn")


_ORIGINAL_SOCKET = None

def socks_monkey_patch(proxy_info: dict = None):
    import socks
    import socket
    global _ORIGINAL_SOCKET

    if proxy_info["username"] and proxy_info["password"]:
        socks.set_default_proxy(
            socks.SOCKS5 if proxy_info["type"] == "SOCKS5" else socks.SOCKS4,
            proxy_info["host"],
            proxy_info["port"],
            username=proxy_info["username"],
            password=proxy_info["password"]
        )
    else:
        socks.set_default_proxy(
            socks.SOCKS5 if proxy_info["type"] == "SOCKS5" else socks.SOCKS4,
            proxy_info["host"],
            proxy_info["port"],
        )

    _ORIGINAL_SOCKET = socket.socket  # save our socket before patching monkey patching socks
    socket.socket = socks.socksocket


def http_monkey_patch(proxy_info: dict = None):
    if proxy_info and proxy_info["type"] == "HTTP":
        proxy_str = f"{proxy_info['host']}:{proxy_info['port']}"
        if proxy_info["username"] and proxy_info["password"]:
            proxy_str = f"{proxy_info['username']}:{proxy_info['password']}@{proxy_str}"

        proxy_handler = request.ProxyHandler({
            'http': 'http://' + proxy_str,
            'https': 'http://' + proxy_str
        })

        opener = request.build_opener(proxy_handler)
        request.install_opener(opener)


def undo_monkey_patching():
    # This undos the custom opener for urllib
    request.install_opener(request.build_opener())

    # This tries to undo the monkey patching we did using Pysocks
    if _ORIGINAL_SOCKET:
        import socket
        socket.socket = _ORIGINAL_SOCKET


# Helper function to encode a form field
def encode_field(name: str, value: str, boundary: str, CRLF: str) -> bytes:
    return (
        f'--{boundary}{CRLF}'
        f'Content-Disposition: form-data; name="{name}"{CRLF}{CRLF}'
        f'{value}{CRLF}'
    ).encode("utf-8")

# Helper function to encode a file field
def encode_file(name: str, filename: str, data: bytes, boundary: str, CRLF: str, content_type: str = "application/octet-stream") -> bytes:
    return (
        f'--{boundary}{CRLF}'
        f'Content-Disposition: form-data; name="{name}"; filename="{filename}"{CRLF}'
        f'Content-Type: {content_type}{CRLF}{CRLF}'
    ).encode("utf-8") + data + CRLF.encode("utf-8")



def http_request(url: str, method: str, auth_token: str = None, metadata: dict = None, blob: bytes = None, longpoll: int = None) -> bytes:
    if method.upper() not in ["POST", "GET", "PUT", "DELETE"]:
        raise ValueError(f"Invalid request method `{method}`")


    if method.upper() in ["POST", "PUT"]:
        if metadata and blob:

            # a-zA-Z0-9, same as what Chromium-based browser do.
            ALPHABET_ASCII  = string.ascii_letters + string.digits
            ALPHABET_LENGTH = len(ALPHABET_ASCII)

            boundary = "WebKitFormBoundary"
            boundary += ''.join(ALPHABET_ASCII[b % ALPHABET_LENGTH] for b in sha3_512(secrets.token_bytes(16))[:16])

            CRLF = "\r\n"
            body = b""

            body += encode_field("metadata", json.dumps(metadata), boundary, CRLF)

            body += encode_file("blob", "blob.bin", blob, boundary, CRLF)

            if not body.endswith(CRLF.encode("utf-8")):
                body += CRLF.encode("utf-8")


            body += f'--{boundary}--{CRLF}'.encode("utf-8")


            req = request.Request(
                url,
                data = body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                method = method.upper()
            )

        elif metadata:
            metadata = json.dumps(metadata).encode("utf-8")
            req = request.Request(url, data=metadata, method=method.upper())
            req.add_header("Content-Type", "application/json")
        else:
            raise ValueError("Request method is POST/PUT but no metadata nor blob were given.")

    else:
        req = request.Request(url, method=method.upper())

    if auth_token is not None:
        req.add_header("Authorization", "Bearer " + auth_token)


    # NOTE: urllib raises a HTTPError for status code >= 400
    try:
        with request.urlopen(req, timeout = longpoll) as response:
            return response.read()

    except urllib.error.HTTPError as e:
        body = e.read().decode()
        logger.error("We received error from server: %s", body)
        raise Exception(body)
