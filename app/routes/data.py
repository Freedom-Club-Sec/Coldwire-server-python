from fastapi import APIRouter, Request, Response, Depends
from app.logic.data import check_new_data
from app.utils.jwt import verify_jwt_token
import asyncio

router = APIRouter()


@router.get("/data/longpoll")
async def get_data_longpoll(request: Request, response: Response, user=Depends(verify_jwt_token)):
    for _ in range(30):
        if await request.is_disconnected():
            # Don't attempt to check for new data if client disconnects before 30 seconds
            # This is crucial to perserve data as they get deleted after being read 
            return

        messages = await asyncio.to_thread(check_new_data, user["id"])

        if messages:
            return {"messages": messages}

        await asyncio.sleep(1)

    return {"messages": []}
