from fastapi import APIRouter, Request, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.utils.helper_utils import valid_b64
from app.logic.authentication import handle_authentication, check_id_public_key
import secrets
import asyncio

router = APIRouter()

# We don't use pydantic base64 validators because they suck and overcomplicate things :)

class InitPayload(BaseModel):
    public_key: str
    user_id: str

class VerifyPayload(BaseModel):
    signature: str
    challenge: str

challenges_tmp = {}
challenges_lock = asyncio.Lock()

@router.post("/authenticate/init")
async def authenticate_init(payload: InitPayload, response: Response):
    public_key = payload.public_key
    user_id    = payload.user_id

    if not valid_b64(public_key):
        raise HTTPException(status_code=400, detail="Invalid base64 for public_key")
 
    # Dilithium5 public-key size is always 2592 bytes
    if len(b64decode(public_key, validate=True)) != 2592:
        raise HTTPException(status_code=400, detail=f"Your signing key must be Dilithium5!")

    
    # if this is a login..
    if len(user_id) != 0 and ( (not user_id.isdigit()) or len(user_id) != 16):
        raise HTTPException(status_code=400, detail="Invalid user_id")

    challenge = b64encode(secrets.token_bytes(32)).decode()

    async with challenges_lock:
        challenges_tmp[challenge] = [user_id, public_key]

    return {"challenge": challenge}



@router.post("/authenticate/verify")
async def authenticate_verify(payload: VerifyPayload):
    signature  = payload.signature
    challenge  = payload.challenge

    if not (valid_b64(signature) or valid_b64(challenge)):
        raise HTTPException(400, "Invalid base64 for signature or challenge")
    

    try:
        user_id, public_key = challenges_tmp.get(challenge)
    except TypeError:
        raise HTTPException(400, "Invalid challenge")

    public_key = b64decode(public_key)

    if user_id != "":
        # check if user_id exists, and is tied to the same public_key user provided
        does_exist_and_matches = await asyncio.to_thread(check_id_public_key, user_id, public_key)
        if not does_exist_and_matches:
            raise HTTPException(400, "Invalid user_id")

    try:
        is_valid = await asyncio.to_thread(verify_signature, "Dilithium5", b64decode(challenge), b64decode(signature), public_key)

        if not is_valid:
            raise HTTPException(400, "Bad signature")
    except Exception:
        raise HTTPException(400, "Not sure how you reached here, but your data is malformed")

    async with challenges_lock:
        challenges_tmp.pop(challenge, None)

    user_id, user_token = await asyncio.to_thread(handle_authentication, public_key, user_id)

    return {"status": "success", "user_id": user_id, "token": user_token}

    
