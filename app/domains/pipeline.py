import threading
from concurrent.futures import ThreadPoolExecutor
from app.core import state
from app.domains.explain.explainer import explain_risk
from app.domains.rag.queries import build_situation_query
from app.domains.rag.retriever import search_nist
from app.domains.scoring.grouping import compute_grouped_scores
from app.domains.scoring.weights import (
    RELATED_CONTROL_MAX_DISTANCE,
    RETRIEVAL_HIGH_CONFIDENCE_DISTANCE,
    RETRIEVAL_LOW_CONFIDENCE_DISTANCE,
)

_lock = threading.Lock()
_grouped: dict[int, list[dict]] = {}
_enrich: dict[tuple[int, str], dict] = {}
TOP_N = 5
LLM_CONCURRENCY = 2
RETRIEVE_K = 8
RELATED_CONTROLS = 2


def invalidate() -> None:
    with _lock:
        _grouped.clear()
        _enrich.clear()


def get_grouped() -> tuple[list[dict], bool]:
    version = state.DATA_VERSION
    with _lock:
        hit = _grouped.get(version)
    if hit is not None:
        return (hit, True)
    computed = compute_grouped_scores()
    with _lock:
        _grouped[version] = computed
    return (computed, False)


def get_top_risks(n: int = TOP_N) -> tuple[list[dict], bool]:
    grouped, grouped_hit = get_grouped()
    top = grouped[:n]
    version = state.DATA_VERSION
    with _lock:
        cached = {r["risk_id"]: _enrich.get((version, r["risk_id"])) for r in top}
    missing = [r for r in top if cached[r["risk_id"]] is None]
    all_hit = grouped_hit and (not missing)
    if missing:
        searched = [(r, search_nist(build_situation_query(r), top_k=RETRIEVE_K)) for r in missing]

        def _confidence_band(distance):
            if distance is None:
                return None
            if distance < RETRIEVAL_HIGH_CONFIDENCE_DISTANCE:
                return "high"
            if distance <= RETRIEVAL_LOW_CONFIDENCE_DISTANCE:
                return "medium"
            return "low"

        def _related(hits, primary_id):
            out, seen = [], {primary_id}
            for h in hits:
                control_id = h.get("control_id")
                distance = h.get("distance")
                if control_id in seen:
                    continue
                if distance is not None and distance > RELATED_CONTROL_MAX_DISTANCE:
                    continue
                seen.add(control_id)
                out.append(
                    {
                        "control_id": control_id,
                        "control_name": h.get("control_name"),
                        "page": h.get("page"),
                        "distance": h.get("distance"),
                        "confidence": _confidence_band(h.get("distance")),
                    }
                )
                if len(out) == RELATED_CONTROLS:
                    break
            return out

        def build(pair):
            risk, hits = pair
            hit = hits[0] if hits else None
            return (
                risk["risk_id"],
                {
                    "related_controls": _related(hits[1:], (hit or {}).get("control_id")),
                    "nist_control_id": (hit or {}).get("control_id"),
                    "nist_control_name": (hit or {}).get("control_name"),
                    "nist_control_excerpt": (hit or {}).get("text"),
                    "nist_page": (hit or {}).get("page"),
                    "retrieval_distance": (hit or {}).get("distance"),
                    "retrieval_confidence": _confidence_band((hit or {}).get("distance")),
                    "explanation": explain_risk(risk, hit),
                },
            )

        with ThreadPoolExecutor(max_workers=min(LLM_CONCURRENCY, len(searched))) as pool:
            for risk_id, enrichment in pool.map(build, searched):
                cached[risk_id] = enrichment
                with _lock:
                    _enrich[version, risk_id] = enrichment
    return ([{**r, **cached[r["risk_id"]]} for r in top], all_hit)


def warm_top_risks() -> None:
    get_top_risks()
