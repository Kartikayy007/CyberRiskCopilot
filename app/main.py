import asyncio
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.endpoints.router import api_router
from app.core import state
from app.domains import pipeline
from app.domains.ingest import bootstrap


def _warm() -> None:
    try:
        bootstrap.load_heavy()
    except Exception:
        return
    try:
        pipeline.warm_top_risks()
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    if state.STATUS is state.IngestStatus.IDLE:
        bootstrap.load_structured()
        bootstrap.preload_embedder()
        asyncio.create_task(asyncio.to_thread(_warm))
    yield


app = FastAPI(title="Cyber Risk Copilot", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Cache"],
)
app.include_router(api_router)
