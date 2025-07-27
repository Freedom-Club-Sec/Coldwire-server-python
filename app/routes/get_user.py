from fastapi import APIRouter, Request, HTTPException, Response, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from base64 import b64encode, b64decode
from app.core.crypto import verify_signature
from app.utils.helper_utils import valid_b64
from app.logic.get_user import check_user
import asyncio

router = APIRouter()


# The reason we dont specify the id as int is because it can trailing digits
class GetUserParams(BaseModel):
    user_id: str

@router.get("/get_user")
async def get_user(response: Response, params: GetUserParams = Depends()):
    user_id = params.user_id

    if (not user_id.isdigit()) or len(user_id) != 16:
        raise HTTPException(status_code=400, detail="Invalid user_id")

    user_exists = check_user(user_id)
    if not user_exists:
        return {"status": "failure", "error": "User ID does not exist"}

    return {"status": "success"}
