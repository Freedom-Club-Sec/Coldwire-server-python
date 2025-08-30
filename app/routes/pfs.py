from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.pfs import ephemeral_keys_processor
from app.utils.helper_utils import valid_b64
from app.utils.jwt import verify_jwt_token
from app.core.constants import (
    ML_KEM_1024_PK_LEN,
    ML_DSA_87_SIGN_LEN,
    CLASSIC_MCELIECE_8_F_PK_LEN,
    KEYS_HASH_CHAIN_LEN
)
import asyncio

router = APIRouter()


class SendKeysPFS(BaseModel):
    publickeys_hashchain: str
    hashchain_signature: str
    pfs_type           : str
    recipient          : str



@router.post("/pfs/send_keys")
async def pfs_send_keys(payload: SendKeysPFS, response: Response, user=Depends(verify_jwt_token)):
    publickeys_hashchain = payload.publickeys_hashchain
    hashchain_signature  = payload.hashchain_signature
    pfs_type             = payload.pfs_type
    recipient            = payload.recipient

    user_id = user["id"]


    if not valid_b64(publickeys_hashchain):
        raise HTTPException(status_code=400, detail="Malformed public_key base64 encoding")
    

    # ML-KEM-1024 public-key size is always exactly 1568 bytes according to spec
    # And 64 bytes for our SHA3-512 hash-chain
    if pfs_type == "partial":
        if len(b64decode(publickeys_hashchain)) != ML_KEM_1024_PK_LEN + KEYS_HASH_CHAIN_LEN:
            raise HTTPException(status_code=400, detail="Malformed public_keys")
    
    # Classic McEliece8192128 public-key size is always exactly 1357824 bytes according to spec
    # And 64 bytes for our SHA3-512 hash-chain
    elif pfs_type == "full":
        if len(b64decode(publickeys_hashchain)) != CLASSIC_MCELIECE_8_F_PK_LEN + ML_KEM_1024_PK_LEN + KEYS_HASH_CHAIN_LEN:
            raise HTTPException(status_code=400, detail="Malformed public_keys")

    else:
        raise HTTPException(status_code=400, detail="Malformed pfs_type")


    if (not valid_b64(hashchain_signature)) or len(b64decode(hashchain_signature)) != ML_DSA_87_SIGN_LEN:
        raise HTTPException(status_code=400, detail="Malformed signature")


    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(ephemeral_keys_processor, user_id, recipient, publickeys_hashchain, hashchain_signature, pfs_type)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}

