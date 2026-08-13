from fastapi import APIRouter

from app.endpoints.data import routes as data
from app.endpoints.health import routes as health
from app.endpoints.ingest import routes as ingest
from app.endpoints.nist import routes as nist
from app.endpoints.risks import routes as risks

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(ingest.router, tags=["ingest"])
api_router.include_router(data.router, tags=["data"])
api_router.include_router(risks.router, tags=["risks"])
api_router.include_router(nist.router, tags=["nist"])
