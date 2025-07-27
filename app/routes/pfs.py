from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from typing import Optional
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.pfs import check_new_pfs_messages, ephemeral_keys_processor
from app.utils.helper_utils import valid_b64
from app.utils.jwt import verify_jwt_token
import asyncio

router = APIRouter()


class SendKeysPFS(BaseModel):
    kyber_publickey_hashchain: str
    kyber_hashchain_signature: str
    recipient                : str



@router.post("/pfs/send_keys")
async def pfs_send_keys(payload: SendKeysPFS, response: Response, user=Depends(verify_jwt_token)):
    kyber_publickey_hashchain = payload.kyber_publickey_hashchain
    kyber_hashchain_signature = payload.kyber_hashchain_signature
    recipient                 = payload.recipient

    user_id = user["id"]


    # Kyber1024 public-key size is always exactly 1568 bytes according to spec
    # And 64 bytes for our SHA3-512 hash-chain
    if (not valid_b64(kyber_publickey_hashchain)) or len(b64decode(kyber_publickey_hashchain)) != 1568 + 64:
        raise HTTPException(status_code=400, detail="Malformed kyber_public_key")


    # Dilithium5 signature is always 4595
    if (not valid_b64(kyber_hashchain_signature)) or len(b64decode(kyber_hashchain_signature)) != 4595:
        raise HTTPException(status_code=400, detail="Malformed kyber_signature")


    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(ephemeral_keys_processor, user_id, recipient, kyber_publickey_hashchain, kyber_hashchain_signature)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}

