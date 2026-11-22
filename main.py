from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.config import get_settings
from app.github_client import GitHubClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    client = GitHubClient(settings)
    app.state.github_client = client

    try:
        yield
    finally:
        await client.close()


app = FastAPI(
    title="PULSE GitHub Agent",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "pulse-github-agent",
    }
