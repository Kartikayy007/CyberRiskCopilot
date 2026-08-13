import re
import json
import time
from pydantic import BaseModel, Field, ValidationError
from app.core.config import settings
from app.domains.explain import prompts
from app.domains.explain.client import (
    MAX_ATTEMPTS,
    RETRY_BACKOFF_SECONDS,
    complete_json,
    is_retryable,
)

MAX_FIELD_CHARS = 600


class RiskExplanation(BaseModel):
    why_it_ranks: str = Field(min_length=1)
    remediation: str = Field(min_length=1)


def _tidy(text: str) -> str:
    return " ".join(str(text).split())[:MAX_FIELD_CHARS]


_SECTION_STOPS = ("Discussion:", "Related Controls:", "Control Enhancements:", "References:")


def _extract_requirements(chunk: str, limit: int = 2) -> str:
    if not chunk:
        return ""
    body = chunk.split("\n", 1)[1] if "\n" in chunk else chunk
    for stop in _SECTION_STOPS:
        body = body.split(stop)[0]
    if "Control:" in body:
        body = body.split("Control:", 1)[1]
    body = " ".join(body.split())
    parts = re.split(r"(?<=[.;])\s+(?=[a-z]\.\s|[A-Z0-9])", body)
    picked = []
    for p in parts:
        p = re.sub(r"^[a-z]\.\s+", "", p.strip())
        if len(p) < 40:
            continue
        if p.lower().startswith(("control:", "references", "related controls", "discussion")):
            continue
        picked.append(p.rstrip(";") + ("" if p.endswith(".") else "."))
        if len(picked) == limit:
            break
    return " ".join(picked)


def _fallback(
    risk: dict, control_id: str | None, control_name: str | None, page, chunk: str = ""
) -> dict:
    services = ", ".join(risk.get("business_services") or []) or "an unmapped service"
    intel = (risk.get("threat_intel") or [{}])[0]
    reasons = [f"affects {risk.get('asset_count')} asset(s) supporting {services}"]
    if risk.get("max_criticality"):
        reasons.append(f"business criticality {risk['max_criticality']}")
    if risk.get("internet_exposed_asset_count"):
        reasons.append(f"{risk['internet_exposed_asset_count']} of them internet-exposed")
    if risk.get("kev_matched"):
        reasons.append("listed in the CISA KEV catalog as actively exploited")
    if intel.get("campaign_name"):
        reasons.append(
            f'matched to the "{intel['campaign_name']}" campaign attributed to {intel.get('threat_actor')}'
        )
    control = f"{control_id} ({control_name})" if control_id else "the retrieved NIST control"
    requirement = _extract_requirements(chunk)
    remediation = (
        f"Apply {control} from NIST SP 800-53 Rev.5"
        + (f", p.{page}" if page is not None else "")
        + f", to {risk.get('vulnerability_name')} on the affected assets."
    )
    if requirement:
        remediation += f" The control requires: {_tidy(requirement)}"
    return {
        "why_it_ranks": f"Scores {risk.get('score')} because it " + "; ".join(reasons) + ".",
        "remediation": remediation,
        "source": "fallback",
    }


def explain_risk(risk: dict, hit: dict | None) -> dict:
    hit = hit or {}
    chunk = hit.get("text", "")
    control_id = hit.get("control_id")
    control_name = hit.get("control_name")
    page = hit.get("page")
    if not chunk or not settings.groq_api_key():
        return _fallback(risk, control_id, control_name, page, chunk)
    prompt = prompts.build_prompt(risk, control_id, control_name, chunk)
    for attempt in range(MAX_ATTEMPTS):
        try:
            raw = complete_json(
                prompt if attempt == 0 else prompt + prompts.RETRY_SUFFIX,
                temperature=0.2 if attempt == 0 else 0.0,
            )
            parsed = RiskExplanation.model_validate(json.loads(raw))
            return {
                "why_it_ranks": _tidy(parsed.why_it_ranks),
                "remediation": _tidy(parsed.remediation),
                "source": "llm",
            }
        except (json.JSONDecodeError, ValidationError, KeyError, TypeError):
            continue
        except Exception as e:
            if is_retryable(e) and attempt < MAX_ATTEMPTS - 1:
                time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
                continue
            break
    return _fallback(risk, control_id, control_name, page, chunk)
