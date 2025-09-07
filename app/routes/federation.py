from fastapi import APIRouter, HTTPException, Request, Response, Depends, Form, UploadFile, File
from app.logic.federation_utils import federation_processor, get_federation_info
from app.logic.config_parser import config
import asyncio
import json

router = APIRouter()


if config["federation_enabled"]:
    @router.get("/federation/info")
    async def federation_info(request: Request, response: Response):
        data = await asyncio.to_thread(get_federation_info)

        return data



    @router.post("/federation/send")
    async def federation_send(metadata: str = Form(...), blob: UploadFile = File(...)):
        metadata = json.loads(metadata)

        if "recipient" not in metadata:
            raise HTTPException(status_code=400, detail="Missing recipient")

        if not metadata["recipient"].isdigit():
            raise HTTPException(status_code=400, detail="Malformed recipient")


        if "sender" not in metadata:
            raise HTTPException(status_code=400, detail="Missing sender")
        
        if not metadata["sender"].isdigit():
            raise HTTPException(status_code=400, detail="Malformed sender")

        if "url" not in metadata:
            raise HTTPException(status_code=400, detail="Missing url")
        


        blob_data = await blob.read()
        if not blob_data:
            raise HTTPException(status_code=400, detail="Empty blob is not allowed")

        recipient = metadata["recipient"]
        sender = metadata["sender"]
        url    = metadata["url"]

        # try:
        await asyncio.to_thread(federation_processor, url, sender, recipient, blob_data)
        # except Exception as e:
        # raise HTTPException(status_code=400, detail = str(e))


        return {"status": "success"}

