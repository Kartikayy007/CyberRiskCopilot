# Cyber Risk Copilot

An AI-powered cyber risk assistant for the TawasolPay scenario. It joins asset
inventory, open vulnerabilities, threat intelligence, business-service context
and the CISA KEV catalogue into a ranked top-5 risk list, and retrieves the
applicable remediation control from the real NIST SP 800-53 Rev. 5 document.

## Live demo

| | URL |
|---|---|
| Frontend | https://cyber-risk-copilot.vercel.app |
| API + report | https://cyberriskcopilot.onrender.com/report |
| OpenAPI | https://cyberriskcopilot.onrender.com/docs |

The backend runs on a free Render instance, which sleeps after 15 minutes of
inactivity — the first request after a sleep takes ~60 seconds to wake.

## Stack

FastAPI · pandas · `all-MiniLM-L6-v2` embeddings via ChromaDB's onnxruntime
embedding function · ChromaDB · Groq `openai/gpt-oss-120b` ·
Next.js + React + TypeScript.

Embeddings run on onnxruntime rather than sentence-transformers/torch: torch put
resident memory past the 512 MB ceiling on every free host. The weights are the
same model, and retrieval distances matched the torch build to ±0.001.

Requires **Python 3.12+** and **Node 20+**.

## How it satisfies the brief

| Requirement | Where |
|---|---|
| Rank top 5, not by CVSS alone | 9 weighted components, CVSS is 0.18 — `GET /risks/top5` |
| Asset, vulnerability, matched intel, business service, plain-English reason | every entry in `GET /report` |
| Remediation retrieved from the actual NIST document | `POST /nist/search`, and the control cited on each risk |
| Human-readable output | `GET /report` returns markdown prose |

The ranking is deterministic and computed in pandas. **The language model never
ranks anything** — it only turns already-selected evidence into prose.

## Run locally

### Backend

macOS / Linux:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # set GROQ_API_KEY
uvicorn app.main:app --port 8000
```

Windows (PowerShell):

```powershell
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env         # set GROQ_API_KEY
uvicorn app.main:app --port 8000
```

Ingest runs automatically on startup in the background. `/health` answers
immediately and reports the stage (`loading_embedding_model`,
`fetching_cisa_kev`, `embedding_nist_800_53`, `ready`). The risk endpoints
return 503 with `Retry-After` until ingest completes.

**First run downloads the NIST PDF (~6 MB) and the ONNX model (~79 MB), then
embeds 861 control chunks — allow 3–5 minutes.** Later runs reuse the persisted `chroma_store/`. Run a **single
worker**: state is per-process and parallel workers would each build their own
vector store against the same SQLite file.

### Frontend

```bash
cd frontend
npm install
echo "NEXT_PUBLIC_API_BASE=http://localhost:8000" > .env.local
npm run dev
```

Open `http://localhost:3000`.

### Environment variables

| Variable | Purpose |
|---|---|
| `GROQ_API_KEY` | Groq key. Without it the system still runs and falls back to extracting the control text verbatim. |
| `GROQ_MODEL` | Defaults to `openai/gpt-oss-120b`. |
| `ADMIN_TOKEN` | Enables `POST /ingest` and `?nocache=true`. **If unset, those routes are disabled (503), not open.** Send as `X-Admin-Token`. |
| `CORS_ORIGINS` | Comma-separated allowed origins. Defaults to `http://localhost:3000`. Not a wildcard. |
| `CHROMA_PERSIST_DIR`, `NIST_800_53_PDF_PATH` | Cache locations. |
| `NEXT_PUBLIC_API_BASE` | Frontend → backend URL. |

## How ranking works

| Component | Weight | Source |
|---|---|---|
| `cvss` | 0.18 | vulnerabilities.csv |
| `exposure` | 0.18 | internet-facing asset or vuln exposure |
| `exploit_or_kev` | 0.18 | exploit available + present in CISA KEV |
| `campaign_match` | 0.18 | matched local threat-intel row (1.0 ransomware, 0.6 otherwise) |
| `kev_ransomware_history` | 0.04 | CISA `knownRansomwareCampaignUse` |
| `business_impact` | 0.14 | criticality, revenue impact, RTO, compliance scope |
| `control_gap` | 0.03 | EDR missing **where EDR is applicable** |
| `patch_constraint` | 0.02 | no vendor patch exists |
| `aging` | 0.05 | `days_open`, saturating at 180 days |

Findings are grouped by identifier, so one flaw on three servers is one entry
listing three assets rather than three rows.

Evidence that CVSS does not dominate: an internet-exposed, KEV-listed,
campaign-matched finding scores **0.9392**, while the highest-CVSS internal
finding with no campaign evidence (CVSS 8.8) scores **0.3066**.

Current top 5:

| # | Risk | Score | Control |
|---|---|---|---|
| 1 | CVE-2023-4966 — Citrix ADC Session Token Leak (CitrixBleed) | 0.9404 | IA-2 (p.161) |
| 2 | CVE-2023-22527 — Confluence RCE via OGNL Injection | 0.9046 | SI-2 (p.360) |
| 3 | CVE-2023-22515 — Atlassian Jira Server-Side Template Injection | 0.9027 | SI-2 (p.360) |
| 4 | CVE-2024-21762 — Fortinet SSL-VPN Heap Buffer Overflow RCE | 0.9010 | SI-2 (p.360) |
| 5 | CVE-2024-55591 — Fortinet FortiOS Authentication Bypass | 0.8954 | IA-2 (p.161) |

## Endpoints

`/docs` has the live OpenAPI spec.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Always 200; status and stage in the body |
| `GET /ready` | 503 until ingest completes |
| `GET /ingest/status` | Counts, degraded flags, data-quality reconciliation |
| `POST /ingest` | Manual refresh — **requires `X-Admin-Token`** |
| `GET /assets`, `/vulnerabilities`, `/threat-intel` | Raw structured data |
| `GET /risks/scored` | All 114 findings with per-component score breakdown |
| `GET /risks/top5` | Top 5 with evidence, NIST control and explanation |
| `GET /report` | The same five as human-readable markdown |
| `POST /nist/search` | Direct retrieval against the NIST corpus |

`?nocache=true` also requires `X-Admin-Token`, because it forces fresh model calls.

## Supporting question 1 — the data split

**Embedded (vector search): only NIST SP 800-53 Rev. 5.** It is 492 pages of
unstructured prose where "which control applies to this situation" is a semantic
question with no key to join on. It is chunked one-chunk-per-control so every
chunk carries its own control ID, which means the control we cite is parsed
metadata rather than something the model inferred.

**Queried as structured records: all five CSVs, the MDR report and the CISA KEV
catalogue.** These have exact join keys — `asset_id`, `cve`,
`business_service` — and the questions asked of them ("is this asset
internet-facing", "is this CVE in KEV") are lookups with correct answers.
Embedding them would convert deterministic joins into similarity guesses and
make the ranking unreproducible. The split is visible in the source tree:
`app/domains/ingest` and `app/domains/scoring` never touch embeddings, and
`app/domains/rag` is the only package that does.

## Supporting question 2 — where it goes wrong

**1. Identifier mismatches silently drop evidence.** Of 114 vulnerability rows,
47 use synthetic `CVE-SYN-*` identifiers and 27 are non-CVE control findings;
none can ever match CISA KEV, so they are scored as not-actively-exploited. This
is not hypothetical — the supplied data contains a real break: threat
intelligence lists `CVE-2025-0333` while the vulnerability file has
`CVE-SYN-2025-0333`, so an intended match is lost. Reconciling the data gives
**24 matching intel rows covering 23 unique identifiers, with 16 unmatched** —
against the brief's stated 25. *Caught by:* `GET /ingest/status` publishes this
reconciliation on every ingest, and `kev_status` is exposed per finding. *Would
add:* identifier normalisation plus an alert when the unmatched rate moves. The
mismatch is deliberately **not** auto-corrected — silently rewriting source
identifiers would hide a real data-quality defect.

**2. NIST retrieval takes the top vector hit regardless of confidence.**
Distances across the current top 5 range 0.60–0.78, but IA-2 (0.775) and SC-23
(0.783) are separated by 0.008, so the "most applicable" control can be a
coin-flip between two defensible answers. A weak match is still displayed.
*Caught by:* every risk carries `retrieval_distance` and a
high/medium/low `retrieval_confidence`, a warning is printed in both the report
and the UI when confidence is low, and up to two related controls are shown so a
near-miss is visible. *Would add:* a labelled gold set of risk→control pairs to
measure recall@k, and a rejection threshold below which the system says "no
confident control" instead of guessing.

**3. The weights are reasoned, not fitted.** No ground truth exists in this
dataset, so the nine weights are judgement calls, and they demonstrably change
the answer: adding `aging` moved the #1 risk, and separating CISA's historical
ransomware flag from a live campaign match removed three findings from the top
ranks. A reviewer could reasonably disagree with the ordering. *Caught by:*
`component_scores` is returned on every finding, so any rank can be audited
factor by factor. *Would add:* a sensitivity sweep and an analyst-labelled
reference ranking to calibrate against.

## Supporting question 3 — one thing I would change

I would build a small evaluation and data-quality suite: a gold set of
risk→control pairs scored for retrieval recall@k, fixture-based checks on the
joins and ranking factors, and data-quality assertions for stale assets, missing
owners and unmatched identifiers. Retrieval is the layer everything downstream
depends on and the only one with no measurement today — every retrieval defect
found so far was found by hand (page-header chunks winning top-1, vendor names
pushing distance from 0.455 to 1.196, citations landing two pages off). Each of
those would have been caught automatically by a recall@k check, and having one
would make weight and prompt changes safe to iterate instead of risky.

## Known limitations

- Weights are heuristic and uncalibrated (see Q2 above).
- Threat-intel **recency, confidence, region and sector are displayed but not
  scored** — a stale global campaign currently counts the same as a live
  regional one.
- `last_seen_days` (stale assets) and `owner_team` (unowned assets) are ingested
  and validated but do not affect ranking.
- Low-confidence retrieval is flagged for review, not suppressed.
- MFA and network-segmentation status are absent from the dataset, so those
  compensating controls are not scored rather than inferred.
- Related controls can vary slightly between restarts — ChromaDB's approximate
  search is not deterministic in the result tail.
- Single-process only; no automated test suite.

## Data pack notes

Ingest validates required columns, duplicate primary keys, and unknown
`asset_id` / `business_service` references, and fails loudly if the MDR report
yields zero campaign sections. All files are read as explicit UTF-8 so the
report's typographic characters parse identically on Windows.

Counts as loaded: 60 assets, 114 vulnerabilities, 40 threat-intel rows, 20
business services, 30 remediation hints, 5 MDR campaigns, 1,665 CISA KEV
records, 861 NIST control chunks, 79 grouped risks.

## Deployment notes

Backend on Render free (Docker, 512 MB), frontend on Vercel.

The 512 MB ceiling is what drove the onnxruntime embedder: with torch, resident
memory sat around 700 MB and the instance OOMs. The `Dockerfile` downloads the
NIST PDF, downloads the ONNX model and embeds all 861 chunks **at build time**,
so the container boots ready — on 0.1 vCPU, doing that work on the first request
would exceed any reasonable health-check grace period.

`HOME` is pinned to `/app` in the image because the ONNX model cache is
home-relative; if the build and runtime users disagree, the 79 MB model is
re-downloaded on every boot. Set `ADMIN_TOKEN` and `CORS_ORIGINS` (the deployed
frontend origin) in production.
