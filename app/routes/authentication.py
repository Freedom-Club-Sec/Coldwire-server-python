from fastapi import APIRouter, HTTPException ,Request, Response
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from typing import Optional
from app.core.crypto import verify_signature
from app.utils.helper_utils import valid_b64
from app.logic.authentication import (
        handle_authentication_init, 
        handle_authentication_jwt, 
        get_challenge_data
)

from app.core.constants import (
    ML_DSA_87_NAME,
    ML_DSA_87_PK_LEN,
    ML_DSA_87_SIGN_LEN
)
import asyncio

router = APIRouter()

class InitPayload(BaseModel):
    public_key: Optional[str] = ""
    user_id   : Optional[str] = ""

class VerifyPayload(BaseModel):
    signature: str
    challenge: str


@router.post("/authenticate/init")
async def authenticate_init(payload: InitPayload, response: Response):
    public_key = payload.public_key
    user_id    = payload.user_id

    if not (user_id or public_key):
        raise HTTPException(status_code=400, detail="Malformed request, you must include either a public_key or a user_id!")

    if public_key:
        if not valid_b64(public_key):
            raise HTTPException(status_code=400, detail="Invalid base64 for public_key")

        if len(b64decode(public_key, validate=True)) != ML_DSA_87_PK_LEN:
            raise HTTPException(status_code=400, detail=f"Malformed {ML_DSA_87_NAME} public_key")

    
    # Check if the user provided a user_id and if yes check if its valid format
    if user_id:
        if len(user_id) != 16 or not user_id.isdigit():
            raise HTTPException(status_code=400, detail="Malformed user_id")

    try:
        challenge = handle_authentication_init(user_id, public_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"challenge": challenge}



@router.post("/authenticate/verify")
async def authenticate_verify(payload: VerifyPayload):
    signature  = payload.signature
    challenge  = payload.challenge

    if (not valid_b64(signature)) or (not valid_b64(challenge)):
        raise HTTPException(status_code=400, detail="Invalid base64 for signature or challenge")
    
    try:
        signature = b64decode(signature)
        if len(signature) != ML_DSA_87_SIGN_LEN:
            raise Exception()
    except Exception:
        raise HTTPException(status_code=400, detail=f"Signature length does not match NIST spec ({len(signature)})")
    

    try:
        user_id, public_key = get_challenge_data(challenge)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid challenge")


    public_key = b64decode(public_key)

    try:
        is_valid_signature = await asyncio.to_thread(verify_signature, ML_DSA_87_NAME, b64decode(challenge), signature, public_key)
        if not is_valid_signature:
            raise Exception()

    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")


    try:
        user_id, user_token = await asyncio.to_thread(handle_authentication_jwt, public_key, user_id)

        return {"status": "success", "user_id": user_id, "token": user_token}
    except Exception:
        raise HTTPException(status_code=400, detail="Public-key is already registered!")

    
