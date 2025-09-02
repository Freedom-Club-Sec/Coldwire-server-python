from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
from app.logic.message import message_processor
from app.utils.helper_utils import valid_b64
from app.utils.jwt import verify_jwt_token
from app.core.constants import (
    ML_DSA_87_SIGN_LEN,
    ML_KEM_1024_CT_LEN,
    CLASSIC_MCELIECE_8_F_CT_LEN,
    KEYS_HASH_CHAIN_LEN,
    OTP_PAD_SIZE 
)
import asyncio

router = APIRouter()

class SendPayload(BaseModel):
    ciphertext_blob: str
    recipient      : str

@router.post("/messages/send")
async def message_send(payload: SendPayload, response: Response, user=Depends(verify_jwt_token)):
    ciphertext_blob = payload.ciphertext_blob
    recipient  = payload.recipient

    user_id = user["id"]

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    
    if (not valid_b64(ciphertext_blob)):
        raise HTTPException(status_code=400, detail="Malformed ciphertext_blob")



    try:
        await asyncio.to_thread(message_processor, user_id, recipient, ciphertext_blob)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=e)

    return {"status": "success"}

