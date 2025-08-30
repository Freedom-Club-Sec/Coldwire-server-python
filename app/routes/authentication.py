from fastapi import APIRouter, HTTPException ,Request, Response
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.utils.helper_utils import valid_b64
from app.logic.authentication import handle_authentication, check_id_public_key, set_verification_challenge, get_challenge_data
from app.core.constants import (
    ML_DSA_87_NAME,
    ML_DSA_87_PK_LEN,
    ML_DSA_87_SIGN_LEN
)
import asyncio

router = APIRouter()

class InitPayload(BaseModel):
    public_key: str
    user_id: str

class VerifyPayload(BaseModel):
    signature: str
    challenge: str


@router.post("/authenticate/init")
async def authenticate_init(payload: InitPayload, response: Response):
    public_key = payload.public_key
    user_id    = payload.user_id

    if not valid_b64(public_key):
        raise HTTPException(status_code=400, detail="Invalid base64 for public_key")

    if len(b64decode(public_key, validate=True)) != ML_DSA_87_PK_LEN:
        raise HTTPException(status_code=400, detail=f"Malformed {ML_DSA_87_NAME} public_key")

    
    # Check if the user provided a user_id and if yes check if its valid format
    if user_id and ( (not user_id.isdigit()) or len(user_id) != 16):
        raise HTTPException(status_code=400, detail="Malformed user_id")

    try:
        challenge = set_verification_challenge(user_id, public_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=e)

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

    # check if user_id exists, and is tied to the same public_key user provided
    if user_id != "":
        does_exist_and_matches = await asyncio.to_thread(check_id_public_key, user_id, public_key)
        if not does_exist_and_matches:
            raise HTTPException(status_code=400, detail="Invalid user_id or public_key")

    try:
        is_valid_signature = await asyncio.to_thread(verify_signature, ML_DSA_87_NAME, b64decode(challenge), signature, public_key)
        if not is_valid_signature:
            raise Exception()

    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")


    user_id, user_token = await asyncio.to_thread(handle_authentication, public_key, user_id)

    return {"status": "success", "user_id": user_id, "token": user_token}

    
