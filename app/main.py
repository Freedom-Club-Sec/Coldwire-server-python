from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.routes import (
        authentication_router,
        get_user_router,
        data_router
)
from app.db.sqlite import init_db
from app.utils.jwt import check_jwt_exists
import logging


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(threadName)s %(message)s"
)
logger = logging.getLogger("coldwire")

check_jwt_exists()
init_db()

app = FastAPI()
app.include_router(authentication_router)
app.include_router(get_user_router)
app.include_router(data_router)
