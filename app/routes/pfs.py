from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from typing import Optional
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.pfs import check_new_pfs_messages, ephemeral_keys_processor
from app.utils.helper_utils import valid_b64
import asyncio
import json
import jwt
import os

router = APIRouter()

auth_scheme = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET")

class SendKeysPFS(BaseModel):
    kyber_public_key: str
    kyber_signature : str
    d5_public_key   : Optional[str] = None
    d5_signature    : Optional[str]  = None
    recipient       : str


def verify_jwt_token(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS512"])
        return payload 
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/pfs/longpoll")
async def get_pfs_longpoll(response: Response, user=Depends(verify_jwt_token)):
    for _ in range(30): 
        messages = await asyncio.to_thread(check_new_pfs_messages, user["id"])
        if messages:
            return JSONResponse(content={"messages": messages})
        await asyncio.sleep(1)

    return JSONResponse(content={"messages": []})



@router.post("/pfs/send_keys")
async def pfs_send_keys(payload: SendKeysPFS, response: Response, user=Depends(verify_jwt_token)):
    kyber_public_key = payload.kyber_public_key
    kyber_signature  = payload.kyber_signature
    d5_public_key    = payload.d5_public_key
    d5_signature     = payload.d5_signature
    recipient        = payload.recipient

    user_id = user["id"]

    # Kyber1024 public-key size is always exactly 1568 bytes according to spec
    if (not valid_b64(kyber_public_key)) or len(b64decode(kyber_public_key)) != 1568:
        raise HTTPException(status_code=400, detail="Malformed kyber_public_key")

    # Dilithium5 public-key size is always 2592 bytes
    if d5_public_key and ((not valid_b64(d5_public_key)) or len(b64decode(d5_public_key)) != 2592):
        raise HTTPException(status_code=400, detail="Malformed d5_public_key")


    # Dilithium5 signature is always 4595
    if (not valid_b64(kyber_signature)) or len(b64decode(kyber_signature)) != 4595:
        raise HTTPException(status_code=400, detail="Malformed kyber_signature")


    if d5_signature and ((not valid_b64(d5_signature)) or len(b64decode(d5_signature)) != 4595):
        raise HTTPException(status_code=400, detail="Malformed d5_signature")

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(ephemeral_keys_processor, user_id, recipient, kyber_public_key, kyber_signature, d5_public_key, d5_signature)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}

