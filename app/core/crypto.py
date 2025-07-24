import oqs

def verify_signature(algorithm: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    with oqs.Signature(algorithm) as verifier:
        return verifier.verify(message, signature, public_key)


