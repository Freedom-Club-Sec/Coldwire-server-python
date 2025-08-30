from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.smp import initiate_new_smp, smp_step_2_processor, smp_step_3_processor, smp_failure_processor
from app.utils.helper_utils import valid_b64, valid_hex
from app.utils.jwt import verify_jwt_token
from app.core.constants import (
    SMP_NONCE_LENGTH
    SMP_PROOF_LENGTH,
    SMP_QUESTION_MAX_LEN,
    ML_DSA_87_PK_LEN
)
import asyncio

router = APIRouter()

class InitiateSMP(BaseModel):
    question: str
    nonce: str
    public_key: str
    recipient: str


class SMP_2(BaseModel):
    proof: str
    nonce: str
    public_key: str
    recipient: str


class SMP_3(BaseModel):
    proof: str
    recipient: str


class SMP_Failure(BaseModel):
    recipient: str


@router.post("/smp/initiate")
async def smp_initiate(payload: InitiateSMP, response: Response, user=Depends(verify_jwt_token)):
    question   = payload.question
    nonce      = payload.nonce
    public_key = payload.public_key
    recipient  = payload.recipient

    user_id = user["id"]

    if (not valid_b64(nonce)) or len(b64decode(nonce)) != SMP_NONCE_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed nonce")

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    if (not valid_b64(public_key)) or len(b64decode(public_key)) != ML_DSA_87_PK_LEN:
        raise HTTPException(status_code=400, detail="Malformed public_key")


    try:
        await asyncio.to_thread(initiate_new_smp, user_id, recipient, question, nonce, public_key)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}



@router.post("/smp/step_2")
async def smp_step_2(payload: SMP_2, response: Response, user=Depends(verify_jwt_token)):
    proof      = payload.proof
    nonce      = payload.nonce
    public_key = payload.public_key
    recipient  = payload.recipient

    user_id = user["id"]

    if (not valid_b64(nonce)) or len(b64decode(nonce)) != SMP_NONCE_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed nonce")
  

    # HMAC SHA512 is fixed-size to 64 bytes
    if (not valid_hex(proof)) or len(bytes.fromhex(proof)) != SMP_PROOF_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed proof")
  
    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")


    if (not valid_b64(public_key)) or len(b64decode(public_key)) != ML_DSA_87_PK_LEN:
        raise HTTPException(status_code=400, detail="Malformed public_key")


    try:
        await asyncio.to_thread(smp_step_2_processor, user_id, recipient, proof, nonce, public_key)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}



@router.post("/smp/step_3")
async def smp_step_3(payload: SMP_3, response: Response, user=Depends(verify_jwt_token)):
    proof     = payload.proof
    recipient = payload.recipient

    user_id = user["id"]

    if (not valid_hex(proof)) or len(bytes.fromhex(proof)) != SMP_PROOF_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed proof")
  
    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(smp_step_3_processor, user_id, recipient, proof)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}


@router.post("/smp/failure")
async def smp_step_3(payload: SMP_Failure, response: Response, user=Depends(verify_jwt_token)):
    recipient = payload.recipient

    user_id = user["id"]

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(smp_failure_processor, user_id, recipient)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}


