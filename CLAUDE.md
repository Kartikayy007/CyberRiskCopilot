# Cyber Risk Copilot — project context

AI Intern take-home assignment: build a system that automatically prioritizes
TawasolPay's cyber risks and retrieves NIST 800-53 remediation guidance.

## Hard requirements (from assignment)

- Top-5 risk ranking must NOT be CVSS-only. Must factor: internet exposure,
  active exploit availability (CISA KEV), threat-actor campaign match,
  business service criticality, missing compensating controls.
- Remediation guidance for each top-5 risk must come from the actual NIST
  SP 800-53 Rev.5 document via RAG (embeddings) — not from LLM training data,
  not from `remediation_guidance.csv` (that CSV is a decoy hint, not the answer).
- Output must be human-readable (structured prose), not raw JSON/CVE list/CVSS table.
- Must be deployed and reachable via a public URL. GitHub repo with README.
- README must answer: (1) data split justification, (2) three specific failure
  modes + mitigations, (3) one thing to improve with more time.

## Architecture decision

- Structured CSVs (assets, vulnerabilities, threat_intelligence,
  business_services) -> queried/joined with pandas filters, NOT embedded.
- NIST 800-53 PDF -> chunked, embedded (sentence-transformers), stored in
  ChromaDB -> this is the only RAG surface.
- CISA KEV catalog -> fetched live, joined on CVE ID (structured, not embedded).
- LLM (Groq) used only for the final plain-English explanation per risk —
  not for scoring, not for retrieval.
- No MCP, no agent/tool-calling framework — deterministic pipeline:
  score -> retrieve -> explain.

## Repo layout

```
app/
  main.py            FastAPI app, router wiring
  state.py           in-memory singleton: loaded dataframes + chroma collection
  data/dataset/       the 5 provided CSVs + threat report (committed)
  data/kev/           cached CISA KEV catalog (gitignored, fetched at runtime)
  data/nist/          cached NIST 800-53 PDF (gitignored, fetched at runtime)
  routers/           health, ingest, data, risks, nist — thin HTTP layer
  services/          data_loader, kev, scoring, llm — business logic
  rag/               nist_ingest (chunk+embed+store), retriever (query)
frontend/            single static page, calls /report and /nist/search
```

## Status

Boilerplate scaffolded. Routers are stubs pending implementation. Core logic
modules (`scoring.py`, `kev.py`, `nist_ingest.py`, `retriever.py`, `llm.py`,
`data_loader.py`) have a first-pass implementation, not yet wired into
routers or tested end-to-end.

## Conventions

- Weights/thresholds in `scoring.py` are a documented starting point, not
  tuned against ground truth — flag this honestly in the README rather than
  presenting the score as authoritative.
- Keep the CSV-vs-embedding split visible in code structure (separate
  `services/` vs `rag/` directories) since it's explicitly evaluated.
