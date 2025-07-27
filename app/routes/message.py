from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.message import otp_batch_processor, otp_message_processor
from app.utils.helper_utils import valid_b64
from app.utils.jwt import verify_jwt_token
import asyncio

router = APIRouter()

class PadsPayload(BaseModel):
    otp_hashchain_ciphertext: str
    otp_hashchain_signature : str 
    recipient               : str

class SendMessagePayload(BaseModel):
    message_encrypted: str
    recipient        : str

@router.post("/messages/send_pads")
async def message_send_pads(payload: PadsPayload, response: Response, user=Depends(verify_jwt_token)):
    otp_hashchain_ciphertext = payload.otp_hashchain_ciphertext
    otp_hashchain_signature  = payload.otp_hashchain_signature
    recipient                = payload.recipient

    user_id = user["id"]
 

    # Kyber1024 ciphertext is always 1568, and since our default One-Time-Pad size is 11 kilobytes
    # We can be confident that the decoded ciphertext_blob size must match 551936 bytes
    # 
    # 11264 / 32 = 352
    # 352 x 1568 = 551936

    if (not valid_b64(otp_hashchain_ciphertext)) or len(b64decode(otp_hashchain_ciphertext)) != 551936:
        raise HTTPException(status_code=400, detail="Malformed otp_hashchain_ciphertext")

    # Dilithium5 signature is always 4595
    if (not valid_b64(otp_hashchain_signature)) or len(b64decode(otp_hashchain_signature)) != 4595:
        raise HTTPException(status_code=400, detail="Malformed otp_hashchain_signature")

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(otp_batch_processor, user_id, recipient, otp_hashchain_ciphertext, otp_hashchain_signature)
    except ValueError as e:
         raise JSONResponse(status_code=400, content={"status": "failure", "error": e})

    return {"status": "success"}


@router.post("/messages/send_message")
async def message_send_message(payload: SendMessagePayload, response: Response, user=Depends(verify_jwt_token)):
    message_encrypted = payload.message_encrypted
    recipient         = payload.recipient

    user_id = user["id"]

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    # 64 is the hash chain output calculated using sha3_512, and 2 is for the padding length field and 1 character is bare minimum for a message
    if len(message_encrypted) < (64 + 2 + 1):
        raise HTTPException(status_code=400, detail="Your message is malformed")

    try:
        await asyncio.to_thread(otp_message_processor, user_id, recipient, message_encrypted)
    except ValueError as e:
         raise JSONResponse(status_code=400, content={"status": "failure", "error": e})

    return {"status": "success"}


