from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.utils.helper_utils import valid_b64
from app.logic.authentication import handle_authentication, check_id_public_key, set_verification_challenge, get_challenge_data
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
        raise JSONResponse(status_code=400, content={"status": "failure", "error": "Invalid base64 for public_key"})

    # Dilithium5 public-key size is always 2592 bytes
    if len(b64decode(public_key, validate=True)) != 2592:
        raise JSONResponse(status_code=400, content={"status": "failure", "error": "Malformed Dilithium5 public_key"})

    
    # Check if the user provided a user_id and if yes check if its valid format
    if len(user_id) != 0 and ( (not user_id.isdigit()) or len(user_id) != 16):
        raise JSONResponse(status_code=400, content={"status": "failure", "error": "Malformed user_id"})

    try:
        challenge = set_verification_challenge(user_id, public_key)
    except ValueError as e:
         raise JSONResponse(status_code=400, content={"status": "failure", "error": e})



    return {"challenge": challenge}



@router.post("/authenticate/verify")
async def authenticate_verify(payload: VerifyPayload):
    signature  = payload.signature
    challenge  = payload.challenge

    if not (valid_b64(signature) or valid_b64(challenge)):
        raise JSONResponse(status_code=400, content={"status": "failure", "error": "Invalid base64 for signature or challenge"})
    

    try:
        user_id, public_key = get_challenge_data(challenge)
    except ValueError:
        raise JSONResponse(status_code=400, content={"status": "failure", "error": "Invalid challenge"})


    # Safe to decode here as we already checked in authenticate_init
    public_key = b64decode(public_key)

    
    # check if user_id exists, and is tied to the same public_key user provided
    if user_id != "":
        does_exist_and_matches = await asyncio.to_thread(check_id_public_key, user_id, public_key)
        if not does_exist_and_matches:
            raise JSONResponse(status_code=400, content={"status": "failure", "error": "Invalid user_id or public_key"})

    try:
        is_valid = await asyncio.to_thread(verify_signature, "Dilithium5", b64decode(challenge), b64decode(signature), public_key)

        if not is_valid:
            raise JSONResponse(status_code=400, content={"status": "failure", "error": "Bad signature"})

    except Exception:
        raise JSONResponse(status_code=400, content={"status": "failure", "error": "Invalid signature base64"})


    user_id, user_token = await asyncio.to_thread(handle_authentication, public_key, user_id)

    return {"status": "success", "user_id": user_id, "token": user_token}

    
