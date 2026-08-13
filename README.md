# Cyber Risk Copilot

AI-powered cyber risk prioritization system for TawasolPay's AI Intern assignment.

## What it does

Joins asset inventory, vulnerability data, threat intelligence, and business
service context into a ranked top-5 risk list, cross-referenced against the
CISA KEV catalog, with remediation guidance retrieved via RAG from the actual
NIST SP 800-53 Rev.5 document.

## Stack

FastAPI, pandas, sentence-transformers, ChromaDB, Groq (Llama), plain HTML/JS frontend.

## Setup

```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in GROQ_API_KEY
uvicorn app.main:app --reload
```

Ingest runs automatically at startup — the endpoints below are live once
`/ready` returns 200. Run a single worker.

## Layout

```
app/core/       config, state, readiness guards, value coercion
app/features/
  ingest/       CSV + CISA KEV loading          } structured-query path
  scoring/      weights, per-asset scoring, grouping, threat-intel join
  rag/          NIST document -> chunks -> embeddings -> retrieval  } embedded path
  explain/      the single LLM call, with a deterministic fallback
  report/       markdown rendering
  pipeline.py   scores -> retrieval -> explanation, version-keyed cache
app/api/        routers + response schemas
```

## Endpoints

See `/docs` for live OpenAPI docs once running.

- `GET /health` — always 200; readiness is in the body. `GET /ready` — 503 until ingest completes
- `POST /ingest` — manual refresh (`?force_rebuild`, `?refresh_kev`); `GET /ingest/status`
- `GET /assets`, `/vulnerabilities`, `/threat-intel` — raw data inspection
- `GET /risks/scored` — every finding with its score breakdown, ungrouped
- `GET /risks/top5` — top 5 risks: affected assets, matched threat intel, retrieved NIST control, explanation
- `GET /report` — the same five as human-readable markdown
- `POST /nist/search` — raw retrieval against the NIST corpus, so the RAG layer is testable on its own

`/risks/top5` and `/report` share a cache; both accept `?nocache=true` and
report `X-Cache: hit|miss`.

## The data split

TODO — answer here: what was embedded (NIST 800-53) vs queried as structured
records (all 5 CSVs), and why.

## Where it goes wrong

TODO — three specific failure modes and mitigations.

## One thing I'd change

TODO.
