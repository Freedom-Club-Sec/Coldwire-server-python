from .authentication import router as authentication_router
from .federation import router as federation_router
from .data import router as data_router


__all__ = ["authentication_router",  "federation_router", "data_router"]
