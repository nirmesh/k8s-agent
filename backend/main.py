from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes import alertmanager, auth, health, investigate, mcp, metrics, remediations
from backend.core.config import settings
from backend.core.logging import logger

app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(investigate.router)
app.include_router(metrics.router)
app.include_router(alertmanager.router)
app.include_router(remediations.router)
app.include_router(mcp.router)


@app.on_event("startup")
def startup() -> None:
    logger.info(f"Starting {settings.app_name}")
