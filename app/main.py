from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import health, ingest, data, risks, nist

app = FastAPI(title="Cyber Risk Copilot")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(data.router)
app.include_router(risks.router)
app.include_router(nist.router)
