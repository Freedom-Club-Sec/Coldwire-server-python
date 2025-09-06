from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.routes import (
        authentication_router,
        federation_router,
        data_router
)
import logging



logging.basicConfig(
    level = logging.getLogger("uvicorn").level,
    format="%(asctime)s [%(levelname)s] %(threadName)s %(message)s"
)
app = FastAPI()
app.include_router(authentication_router)
app.include_router(federation_router)
app.include_router(data_router)
