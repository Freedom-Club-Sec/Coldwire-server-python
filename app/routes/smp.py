from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.smp import (
        initiate_new_smp, 
        smp_step_2_processor, 
        smp_step_3_processor, 
        smp_step_4_processor, 
        smp_step_5_processor, 
        smp_step_6_processor, 
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
    nonce: str
    signing_public_key: str
    recipient: str


class SMP_2(BaseModel):
    nonce: str
    signing_public_key: str
    question_public_key: str
    recipient: str


class SMP_3(BaseModel):
    question_ciphertext: str
    question_pads_ciphertext: str
    recipient: str



class SMP_Proof(BaseModel):
    proof: str
    recipient: str


class SMP_Failure(BaseModel):
    recipient: str


@router.post("/smp/initiate")
async def smp_initiate(payload: InitiateSMP, response: Response, user=Depends(verify_jwt_token)):
    nonce      = payload.nonce
    signing_public_key = payload.signing_public_key
    recipient  = payload.recipient

    user_id = user["id"]

    if (not valid_b64(nonce)) or len(b64decode(nonce)) != SMP_NONCE_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed nonce")

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    if (not valid_b64(signing_public_key)) or len(b64decode(signing_public_key)) != ML_DSA_87_PK_LEN:
        raise HTTPException(status_code=400, detail="Malformed public_key")


    try:
        await asyncio.to_thread(initiate_new_smp, user_id, recipient, nonce, signing_public_key)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}



@router.post("/smp/step_2")
async def smp_step_2(payload: SMP_2, response: Response, user=Depends(verify_jwt_token)):
    nonce      = payload.nonce
    signing_public_key = payload.signing_public_key
    question_public_key = payload.question_public_key
    recipient  = payload.recipient

    user_id = user["id"]

    if (not valid_b64(nonce)) or len(b64decode(nonce)) != SMP_NONCE_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed nonce")
  

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")


    if (not valid_b64(signing_public_key)) or len(b64decode(signing_public_key)) != ML_DSA_87_PK_LEN:
        raise HTTPException(status_code=400, detail="Malformed signing_public_key")

    if (not valid_b64(question_public_key)) or len(b64decode(question_public_key)) != ML_KEM_1024_PK_LEN:
        raise HTTPException(status_code=400, detail="Malformed question_public_key")


    try:
        await asyncio.to_thread(smp_step_2_processor, user_id, recipient, nonce, signing_public_key, question_public_key)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}


@router.post("/smp/step_3")
async def smp_step_3(payload: SMP_3, response: Response, user=Depends(verify_jwt_token)):
    question_pads_ciphertext = payload.question_pads_ciphertext
    question_ciphertext      = payload.question_ciphertext
    recipient                = payload.recipient

    user_id = user["id"]

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")


    if (not valid_b64(question_pads_ciphertext)): # or len(b64decode(question_pads_ciphertext)) != SMP_QUESTION_MAX_LEN:
        raise HTTPException(status_code=400, detail="Malformed question_pads_ciphertext")


    if (not valid_b64(question_ciphertext)) or len(b64decode(question_ciphertext)) > SMP_QUESTION_MAX_LEN:
        raise HTTPException(status_code=400, detail="Malformed question_ciphertext")


    try:
        await asyncio.to_thread(smp_step_3_processor, user_id, recipient, question_pads_ciphertext, question_ciphertext)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}



@router.post("/smp/step_4")
async def smp_step_4(payload: SMP_Proof, response: Response, user=Depends(verify_jwt_token)):
    proof     = payload.proof
    recipient = payload.recipient

    user_id = user["id"]

    if (not valid_hex(proof)) or len(bytes.fromhex(proof)) != SMP_PROOF_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed proof")
  
    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(smp_step_4_processor, user_id, recipient, proof)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}


@router.post("/smp/step_5")
async def smp_step_5(payload: SMP_Proof, response: Response, user=Depends(verify_jwt_token)):
    proof     = payload.proof
    recipient = payload.recipient

    user_id = user["id"]

    if (not valid_hex(proof)) or len(bytes.fromhex(proof)) != SMP_PROOF_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed proof")
  
    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(smp_step_5_processor, user_id, recipient, proof)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}


@router.post("/smp/step_6")
async def smp_step_5(payload: SMP_Proof, response: Response, user=Depends(verify_jwt_token)):
    proof     = payload.proof
    recipient = payload.recipient

    user_id = user["id"]

    if (not valid_hex(proof)) or len(bytes.fromhex(proof)) != SMP_PROOF_LENGTH:
        raise HTTPException(status_code=400, detail="Malformed proof")
  
    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(smp_step_6_processor, user_id, recipient, proof)
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


