import asyncio
import traceback
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core import state
from app.core.config import settings
from app.domains import pipeline
from app.domains.ingest import bootstrap
from app.endpoints.router import api_router


def _warm() -> None:
    try:
        bootstrap.load_heavy()
    except Exception:
        return
    try:
        pipeline.warm_top_risks()
    except Exception:
        state.STATUS_DETAIL["warm_error"] = traceback.format_exc(limit=3)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if state.STATUS is state.IngestStatus.IDLE:
        try:
            bootstrap.load_structured()
        except Exception as e:
            state.STATUS = state.IngestStatus.FAILED
            state.STATUS_DETAIL["stage"] = "failed"
            state.STATUS_DETAIL["error"] = f"{type(e).__name__}: {e}"
            yield
            return
        asyncio.create_task(asyncio.to_thread(_warm))
    yield


app = FastAPI(title="Cyber Risk Copilot", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins(),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Admin-Token"],
    expose_headers=["X-Cache"],
)
app.include_router(api_router)
