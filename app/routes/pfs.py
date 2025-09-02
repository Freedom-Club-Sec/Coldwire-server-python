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
    ciphertext_blob: str
    recipient      : str



@router.post("/pfs/send_keys")
async def pfs_send_keys(payload: SendKeysPFS, response: Response, user=Depends(verify_jwt_token)):
    ciphertext_blob = payload.ciphertext_blob
    recipient  = payload.recipient

    user_id = user["id"]

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    
    if (not valid_b64(ciphertext_blob)):
        raise HTTPException(status_code=400, detail="Malformed ciphertext_blob")


    try:
        await asyncio.to_thread(ephemeral_keys_processor, user_id, recipient, ciphertext_blob)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}

