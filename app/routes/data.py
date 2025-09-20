from fastapi import APIRouter, Request, HTTPException, Response, Depends, Form, UploadFile, File, Query
from app.logic.data import check_new_data, delete_data, data_processor
from app.utils.jwt import verify_jwt_token
from app.core.constants import LONGPOLL_MAX
from typing import Optional
import asyncio
import json

router = APIRouter()


@router.get("/data/longpoll")
async def get_data_longpoll(request: Request, response: Response, acks: Optional[list[str]] = Query(None), user=Depends(verify_jwt_token)):
    if acks:
        await asyncio.to_thread(delete_data, user["id"], acks)
        
    for _ in range(LONGPOLL_MAX):
        if await request.is_disconnected():
            # Don't bother checking for new data if client disconnects before LONGPOLL_MAX seconds
            return Response(content=b'', media_type="application/octet-stream")

        data = await asyncio.to_thread(check_new_data, user["id"])

        if data:
            return Response(content = data, media_type="application/octet-stream")
        await asyncio.sleep(1)

    return Response(content=b'', media_type="application/octet-stream")


@router.post("/data/send")
async def data_send(metadata: str = Form(...), blob: UploadFile = File(...), user=Depends(verify_jwt_token)):
    user_id = user["id"]

    metadata = json.loads(metadata)

    if "recipient" not in metadata:
        raise HTTPException(status_code=400, detail="Missing recipient")

    recipient = metadata["recipient"]

    blob_data = await blob.read()
    if not blob_data:
        raise HTTPException(status_code=400, detail="Empty blob is not allowed")

    try:
        await asyncio.to_thread(data_processor, user_id, recipient, blob_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


    return {"status": "success"}

