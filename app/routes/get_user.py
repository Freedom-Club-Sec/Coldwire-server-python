from fastapi import APIRouter, Request, HTTPException, Response, Depends
from pydantic import BaseModel, validator
from app.logic.get_user import check_user
from app.utils.jwt import verify_jwt_token
import asyncio

router = APIRouter()


class GetUserParams(BaseModel):
    user_id: str

@router.get("/get_user")
async def get_user(response: Response, params: GetUserParams = Depends(), user=Depends(verify_jwt_token)):
    user_id = params.user_id

    if (not user_id.isdigit()) or len(user_id) != 16:
        raise HTTPException(status_code=400, detail="Invalid user_id")

    user_exists = check_user(user_id)
    if not user_exists:
        return {"status": "failure", "error": "User ID does not exist"}

    return {"status": "success"}
