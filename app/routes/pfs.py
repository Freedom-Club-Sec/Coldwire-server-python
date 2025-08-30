from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.pfs import ephemeral_keys_processor
from app.utils.helper_utils import valid_b64
from app.utils.jwt import verify_jwt_token
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
        if len(b64decode(publickeys_hashchain)) != 1568 + 64:
            raise HTTPException(status_code=400, detail="Malformed public_keys")
    
    # Classic McEliece8192128 public-key size is always exactly 1357824 bytes according to spec
    # And 64 bytes for our SHA3-512 hash-chain
    elif pfs_type == "full":
        if len(b64decode(publickeys_hashchain)) != 1357824 + 1568 + 64:
            raise HTTPException(status_code=400, detail="Malformed public_keys")

    else:
        raise HTTPException(status_code=400, detail="Malformed pfs_type")


    # ML-DSA-87 signature is always 4595
    # NOTE: Is it though ?? NIST did change it and liboqs followed.. 
    if (not valid_b64(hashchain_signature)) or len(b64decode(hashchain_signature)) != 4595:
        raise HTTPException(status_code=400, detail="Malformed signature")


    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(ephemeral_keys_processor, user_id, recipient, publickeys_hashchain, hashchain_signature, pfs_type)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}

