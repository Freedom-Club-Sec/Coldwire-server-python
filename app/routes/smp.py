from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.smp import (
        initiate_new_smp, 
        smp_step_processor, 
        smp_failure_processor)
from app.utils.helper_utils import valid_b64, valid_hex
from app.utils.jwt import verify_jwt_token
from app.core.constants import (
    SMP_NONCE_LENGTH,
    SMP_PROOF_LENGTH,
    SMP_QUESTION_MAX_LEN,
    ML_DSA_87_PK_LEN,
    ML_KEM_1024_PK_LEN
)
import asyncio

router = APIRouter()

class InitiateSMP(BaseModel):
    kem_public_key: str
    recipient: str


class SMP_Step(BaseModel):
    ciphertext_blob: str
    recipient: str


class SMP_Failure(BaseModel):
    recipient: str


@router.post("/smp/initiate")
async def smp_initiate(payload: InitiateSMP, response: Response, user=Depends(verify_jwt_token)):
    kem_public_key = payload.kem_public_key
    recipient  = payload.recipient

    user_id = user["id"]


    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    if (not valid_b64(kem_public_key)) or len(b64decode(kem_public_key)) != ML_KEM_1024_PK_LEN:
        raise HTTPException(status_code=400, detail="Malformed public_key")


    try:
        await asyncio.to_thread(initiate_new_smp, user_id, recipient, kem_public_key)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}



@router.post("/smp/step")
async def smp_step(payload: SMP_Step, response: Response, user=Depends(verify_jwt_token)):
    ciphertext_blob = payload.ciphertext_blob
    recipient  = payload.recipient

    user_id = user["id"]

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")



    
    if (not valid_b64(ciphertext_blob)):
        raise HTTPException(status_code=400, detail="Malformed ciphertext_blob")
  

    try:
        await asyncio.to_thread(smp_step_processor, user_id, recipient, ciphertext_blob)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}



@router.post("/smp/failure")
async def smp_failure(payload: SMP_Failure, response: Response, user=Depends(verify_jwt_token)):
    recipient = payload.recipient

    user_id = user["id"]

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(smp_failure_processor, user_id, recipient)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}


