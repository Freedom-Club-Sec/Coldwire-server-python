from nacl import pwhash, bindings
from app.core.constants import (
    ARGON2_ITERS,
    ARGON2_MEMORY,
    ARGON2_LANES,
    ARGON2_OUTPUT_LEN,
    ARGON2_SALT_LEN,
    ML_DSA_87_NAME,
    ML_DSA_87_SK_LEN,
    ML_DSA_87_PK_LEN,
    ML_DSA_87_SIGN_LEN,
    ALGOS_BUFFER_LIMITS
)
import oqs
import hashlib
import secrets

def generate_sign_keys(algorithm: str = ML_DSA_87_NAME) -> tuple[bytes, bytes]:
    """
    Generates a new post-quantum signature keypair.

    Args:
        algorithm: PQ signature algorithm (default ML-DSA-87).

    Returns:
        (private_key, public_key) as bytes.
    """
    with oqs.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return private_key, public_key

def create_signature(algorithm: str, message: bytes, private_key: bytes) -> bytes:
    """
    Creates a digital signature for a message using a post-quantum signature scheme.

    Args:
        algorithm: PQ signature algorithm (e.g. "ML-DSA-87").
        message: Data to sign.
        private_key: Private key bytes.

    Returns:
        Signature bytes of fixed size defined by the algorithm.
    """
    with oqs.Signature(algorithm, secret_key = private_key[:ALGOS_BUFFER_LIMITS[algorithm]["SK_LEN"]]) as signer:
        return signer.sign(message)

def verify_signature(algorithm: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verifies a post-quantum signature.

    Args:
        algorithm: PQ signature algorithm (e.g. "ML-DSA-87").
        message: Original message data.
        signature: Signature to verify.
        public_key: Corresponding public key bytes.

    Returns:
        True if valid, False if invalid.
    """
    with oqs.Signature(algorithm) as verifier:
        return verifier.verify(message, signature[:ALGOS_BUFFER_LIMITS[algorithm]["SIGN_LEN"]], public_key[:ALGOS_BUFFER_LIMITS[algorithm]["PK_LEN"]])


def sha3_512(data: bytes) -> bytes:
    """
    Compute a SHA3-512 hash of the given data.

    Args:
        data: Input bytes to hash.

    Returns:
        A 64-byte SHA3-512 digest.
    """
    h = hashlib.sha3_512()
    h.update(data)
    return h.digest()


def derive_key_argon2id(password: bytes, salt: bytes = None, output_length: int = ARGON2_OUTPUT_LEN) -> tuple[bytes, bytes]:
    """
    Derive a symmetric key from a password using Argon2id.

    If no salt is provided, a new random salt is generated.

    Args:
        password: User-provided password bytes.
        salt: Optional salt bytes; must be of length salt_length.
        salt_length: Length of salt to generate if none is provided.
        output_length: Desired length of derived key.

    Returns:
        A tuple (derived_key, salt) where:
        - derived_key: The Argon2id-derived key of output_length bytes.
        - salt: The salt used for derivation.
    """
    if salt is None:
        salt = secrets.token_bytes(ARGON2_SALT_LEN)

    return pwhash.argon2id.kdf(
        output_length,
        password,
        salt,
        opslimit = ARGON2_ITERS,
        memlimit = ARGON2_MEMORY
    ), salt



