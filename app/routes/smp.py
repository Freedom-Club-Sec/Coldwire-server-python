from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.smp import check_new_smp_messages, initiate_new_smp, smp_step_2_processor, smp_step_3_processor, smp_failure_processor
from app.utils.helper_utils import valid_b64
import asyncio
import jwt
import os

router = APIRouter()

auth_scheme = HTTPBearer()

JWT_SECRET = os.environ.get("JWT_SECRET")

class InitiateSMP(BaseModel):
    question: str
    nonce: str
    recipient: str


class SMP_2(BaseModel):
    proof: str
    nonce: str
    recipient: str


class SMP_3(BaseModel):
    proof: str
    recipient: str


class SMP_Failure(BaseModel):
    recipient: str


def verify_jwt_token(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS512"])
        return payload 
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/get_smp/longpoll")
async def get_smp_longpoll(response: Response, user=Depends(verify_jwt_token)):
    for _ in range(30): 
        messages = await asyncio.to_thread(check_new_smp_messages, user["id"])
        if messages:
            return JSONResponse(content={"messages": messages})
        await asyncio.sleep(1)

    return JSONResponse(content={"messages": []})


@router.post("/smp/initiate")
async def smp_initiate(payload: InitiateSMP, response: Response, user=Depends(verify_jwt_token)):
    question  = payload.question
    nonce     = payload.nonce
    recipient = payload.recipient

    user_id = user["id"]

    if (not valid_b64(nonce)) or len(b64decode(nonce)) != 32:
        raise HTTPException(status_code=400, detail="Malformed nonce")

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(initiate_new_smp, user_id, recipient, question, nonce)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}



@router.post("/smp/step_2")
async def smp_step_2(payload: SMP_2, response: Response, user=Depends(verify_jwt_token)):
    proof     = payload.proof
    nonce     = payload.nonce
    recipient = payload.recipient

    user_id = user["id"]

    if (not valid_b64(nonce)) or len(b64decode(nonce)) != 32:
        raise HTTPException(status_code=400, detail="Malformed nonce")
  

    if (not recipient.isdigit()) or len(recipient) != 16:
        raise HTTPException(status_code=400, detail="Invalid recipient")

    try:
        await asyncio.to_thread(smp_step_2_processor, user_id, recipient, proof, nonce)
    except ValueError as e:
        return {"status": "failure", "error": e}

    return {"status": "success"}



@router.post("/smp/step_3")
async def smp_step_3(payload: SMP_3, response: Response, user=Depends(verify_jwt_token)):
    proof     = payload.proof
    recipient = payload.recipient

    user_id = user["id"]

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


