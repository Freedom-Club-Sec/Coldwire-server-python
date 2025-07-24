from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from typing import Optional
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.message import check_new_messages, one_time_pads_batch_processor, one_time_pads_message_processor
from app.utils.helper_utils import valid_b64
import asyncio
import jwt
import os

router = APIRouter()

auth_scheme = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET")

class MessagePayload(BaseModel):
    json_payload     : str
    payload_signature: str 
    recipient        : str


def verify_jwt_token(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS512"])
        return payload 
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/messages/longpoll")
async def get_messages_longpoll(response: Response, user=Depends(verify_jwt_token)):
    for _ in range(30): 
        messages = await asyncio.to_thread(check_new_messages, user["id"])
        if messages:
            return JSONResponse(content={"messages": messages})
        await asyncio.sleep(1)

    return JSONResponse(content={"messages": []})



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
        await asyncio.to_thread(one_time_pads_batch_processor, user_id, recipient, json_payload, payload_signature)
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
        await asyncio.to_thread(one_time_pads_message_processor, user_id, recipient, json_payload, payload_signature)
    except ValueError as e:
         raise JSONResponse(status_code=400, content={"status": "failure", "error": e})

    return {"status": "success"}


