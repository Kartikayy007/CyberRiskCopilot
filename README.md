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

## Endpoints

See `/docs` for live OpenAPI docs once running.

- `POST /ingest` — load CSVs, fetch CISA KEV, build NIST vector store
- `GET /assets`, `/vulnerabilities`, `/threat-intel` — raw data inspection
- `GET /risks/scored` — full ranked list with score breakdown
- `GET /risks/top5` — top 5 risks with RAG-retrieved NIST guidance + LLM explanation
- `GET /report` — human-readable formatted version of top5
- `POST /nist/search` — raw RAG query against NIST 800-53
- `GET /health`

## The data split

TODO — answer here: what was embedded (NIST 800-53) vs queried as structured
records (all 5 CSVs), and why.

## Where it goes wrong

TODO — three specific failure modes and mitigations.

## One thing I'd change

TODO.
