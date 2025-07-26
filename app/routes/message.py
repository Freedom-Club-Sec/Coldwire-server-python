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

class MessagePayload(BaseModel):
    json_payload     : str
    payload_signature: str 
    recipient        : str


@router.post("/messages/send_pads")
async def message_send_pads(payload: MessagePayload, response: Response, user=Depends(verify_jwt_token)):
    json_payload      = payload.json_payload
    payload_signature = payload.payload_signature
    recipient         = payload.recipient

    user_id = user["id"]

    # Dilithium5 signature is always 4595
    if (not valid_b64(payload_signature)) or len(b64decode(payload_signature)) != 4595:
        raise HTTPException(status_code=400, detail="Malformed payload_signature")

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(otp_batch_processor, user_id, recipient, json_payload, payload_signature)
    except ValueError as e:
         raise JSONResponse(status_code=400, content={"status": "failure", "error": e})

    return {"status": "success"}


@router.post("/messages/send_message")
async def message_send_message(payload: MessagePayload, response: Response, user=Depends(verify_jwt_token)):
    json_payload      = payload.json_payload
    payload_signature = payload.payload_signature
    recipient         = payload.recipient

    user_id = user["id"]

    # Dilithium5 signature is always 4595
    if (not valid_b64(payload_signature)) or len(b64decode(payload_signature)) != 4595:
        raise HTTPException(status_code=400, detail="Malformed payload_signature")

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(otp_message_processor, user_id, recipient, json_payload, payload_signature)
    except ValueError as e:
         raise JSONResponse(status_code=400, content={"status": "failure", "error": e})

    return {"status": "success"}


