from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import PlainTextResponse
from app.endpoints import schemas
from app.core.deps import require_ready
from app.core.sanitize import clean
from app.domains import pipeline
from app.domains.report.markdown import render_report
from app.domains.scoring.scorer import compute_scores

router = APIRouter(dependencies=[Depends(require_ready)])


@router.get("/risks/scored", responses={200: {"model": list[schemas.ScoredRisk]}})
def risks_scored():
    return clean(compute_scores().to_dict("records"))


@router.get("/risks/top5", responses={200: {"model": list[schemas.TopRisk]}})
def risks_top5(response: Response, nocache: bool = Query(False)):
    if nocache:
        pipeline.invalidate()
    risks, was_hit = pipeline.get_top_risks()
    response.headers["X-Cache"] = "hit" if was_hit and (not nocache) else "miss"
    return clean(risks)


@router.get(
    "/report", response_class=PlainTextResponse, responses={200: {"content": {"text/markdown": {}}}}
)
def report(response: Response, nocache: bool = Query(False)):
    if nocache:
        pipeline.invalidate()
    risks, was_hit = pipeline.get_top_risks()
    response.headers["X-Cache"] = "hit" if was_hit and (not nocache) else "miss"
    return render_report(risks)
