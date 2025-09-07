from fastapi import APIRouter, Request, HTTPException, Response, Depends, Form, UploadFile, File
from app.logic.data import check_new_data, data_processor
from app.utils.jwt import verify_jwt_token
from app.core.constants import LONGPOLL_MAX
import asyncio
import json

router = APIRouter()


@router.get("/data/longpoll")
async def get_data_longpoll(request: Request, response: Response, user=Depends(verify_jwt_token)):
    for _ in range(LONGPOLL_MAX):
        if await request.is_disconnected():
            # Don't attempt to check for new data if client disconnects before LONGPOLL_MAX seconds
            # This is crucial to perserve data as they get deleted after being read 
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
        raise HTTPException(status_code=400, detail=e)


    return {"status": "success"}

