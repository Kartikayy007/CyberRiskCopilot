from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.endpoints.schemas import NistSearchResponse
from app.core.deps import require_ready
from app.core.sanitize import clean
from app.domains.rag.retriever import search_nist

router = APIRouter(dependencies=[Depends(require_ready)])


class NistSearchRequest(BaseModel):
    query: str = Field(min_length=1)
    top_k: int = Field(3, ge=1, le=10)


@router.post("/nist/search", response_model=NistSearchResponse)
def nist_search(req: NistSearchRequest):
    return clean({"query": req.query, "results": search_nist(req.query, req.top_k)})
