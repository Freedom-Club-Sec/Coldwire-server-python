from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.logic.smp import check_new_smp_messages
from app.logic.pfs import check_new_pfs_messages
from app.logic.message import check_new_messages
from app.utils.helper_utils import valid_b64
from app.utils.jwt import verify_jwt_token
import asyncio

router = APIRouter()


# We prioritize SMP messages over PFS messages, and PFS messages over new messages
# This is to prevent any race conditions. No PFS messages are supposed to exist before SMP messages
# and no new message should exist before a new PFS message
data_sources = [
    check_new_smp_messages,
    check_new_pfs_messages,
    check_new_messages,
]

@router.get("/data/longpoll")
async def get_data_longpoll(request: Request, response: Response, user=Depends(verify_jwt_token)):
    for _ in range(30):
        if await request.is_disconnected():
            # Don't attempt to check for messages if client disconnects before 30 seconds
            # This is crucial to perserve data as they usually get deleted inside of 
            # their respective functions right after being read.
            return

        all_messages = []

        for checker in data_sources:
            messages = await asyncio.to_thread(checker, user["id"])
            if messages:
                all_messages.extend(messages)

        if all_messages:
            return JSONResponse(content={"messages": all_messages})

        await asyncio.sleep(1)

    return JSONResponse(content={"messages": []})
