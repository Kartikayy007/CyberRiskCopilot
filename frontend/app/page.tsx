"use client";

import { useCallback, useEffect, useRef, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

type AffectedAsset = {
  asset_id: string;
  asset_name: string;
  vuln_id: string;
  vulnerability_name: string;
  business_service: string | null;
  criticality: string | null;
  asset_exposure: string | null;
  internet_exposed: string | null;
  score: number;
};

type ThreatIntel = {
  intel_id: string;
  threat_actor: string | null;
  campaign_name: string | null;
  exploit_maturity: string | null;
  confidence: string | null;
  ransomware_association: boolean;
  active_last_seen: string | null;
  target_sector: string | null;
  target_region: string | null;
  summary: string | null;
};

type Explanation = {
  why_it_ranks: string;
  remediation: string;
  source: "llm" | "fallback";
};

type GroupedRisk = {
  risk_id: string;
  id_type: "cve" | "synthetic_cve" | "control_finding" | "unknown";
  vulnerability_name: string;
  alias_names: string[];
  score: number;
  cvss: number | null;
  severity: string | null;
  asset_count: number;
  internet_exposed_asset_count: number;
  affected_assets: AffectedAsset[];
  business_services: string[];
  max_criticality: string | null;
  kev_matched: boolean;
  kev_status: string | null;
  kev_ransomware_use: boolean;
  kev_required_action: string | null;
  active_campaign_matched: boolean;
  active_ransomware_campaign: boolean;
  threat_intel: ThreatIntel[];
  nist_control_id: string | null;
  nist_control_name: string | null;
  nist_control_excerpt: string | null;
  nist_page: number | null;
  explanation: Explanation;
};

type NistHit = {
  text: string;
  control_id: string | null;
  control_name: string | null;
  page: number | null;
  distance: number;
};

type Status = {
  status: "idle" | "running" | "ready" | "failed";
  stage: string | null;
  nist_chunks?: number;
  kev_records?: number;
  csv_counts?: Record<string, number>;
  degraded?: string[];
  error?: string | null;
};

const ID_LABEL: Record<string, string> = {
  cve: "CVE",
  synthetic_cve: "Synthetic CVE",
  control_finding: "Control gap",
  unknown: "Finding",
};

function Chip({ text, tone = "neutral" }: { text: string; tone?: "neutral" | "danger" | "warn" }) {
  const tones = {
    neutral: "border-neutral-700 text-neutral-300",
    danger: "border-red-800 bg-red-950/40 text-red-300",
    warn: "border-amber-800 bg-amber-950/30 text-amber-300",
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded border ${tones[tone]}`}>{text}</span>
  );
}

export default function Home() {
  const [status, setStatus] = useState<Status | null>(null);
  const [risks, setRisks] = useState<GroupedRisk[]>([]);
  const [loadingRisks, setLoadingRisks] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const [query, setQuery] = useState("");
  const [nistHits, setNistHits] = useState<NistHit[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);

  const loadedRef = useRef(false);

  const loadTop5 = useCallback(async () => {
    setLoadingRisks(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/risks/top5`);
      if (res.status === 503) {
        setError("Still warming up — retrying shortly.");
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setRisks(await res.json());
    } catch (e) {
      setError(`Could not load risks: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoadingRisks(false);
    }
  }, []);

  // The backend ingests on startup, so the page just waits for it to be ready
  // rather than asking the user to trigger anything.
  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE}/ingest/status`);
        const s: Status = await res.json();
        if (cancelled) return;
        setStatus(s);
        if (s.status === "ready" && !loadedRef.current) {
          loadedRef.current = true;
          loadTop5();
        }
        if (s.status !== "ready" && s.status !== "failed") {
          setTimeout(poll, 3000);
        }
      } catch {
        if (!cancelled) setTimeout(poll, 3000);
      }
    };

    poll();
    return () => {
      cancelled = true;
    };
  }, [loadTop5]);

  async function refresh() {
    setRefreshing(true);
    try {
      await fetch(`${API_BASE}/ingest`, { method: "POST" });
      await loadTop5();
    } finally {
      setRefreshing(false);
    }
  }

  async function searchNist() {
    if (!query.trim()) return;
    setSearching(true);
    setSearchError(null);
    try {
      const res = await fetch(`${API_BASE}/nist/search`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, top_k: 3 }),
      });
      if (!res.ok) {
        setSearchError(`Search failed (HTTP ${res.status}).`);
        setNistHits([]);
        return;
      }
      const data = await res.json();
      setNistHits(data.results ?? []);
    } catch (e) {
      setSearchError(e instanceof Error ? e.message : String(e));
      setNistHits([]);
    } finally {
      setSearching(false);
    }
  }

  const warming = status && status.status !== "ready" && status.status !== "failed";

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-100 p-8 max-w-4xl mx-auto">
      <header className="mb-6">
        <h1 className="text-2xl font-bold">Cyber Risk Copilot</h1>
        <p className="text-neutral-400">
          TawasolPay — top 5 risks ranked by exposure, active exploitation, campaign match,
          business criticality and control gaps. Remediation retrieved from NIST SP 800-53 Rev.5.
        </p>
      </header>

      {warming && (
        <div className="mb-6 border border-blue-900 bg-blue-950/30 rounded p-3 text-sm text-blue-200">
          Warming up: {status?.stage?.replace(/_/g, " ") ?? "starting"}. This runs once at startup.
        </div>
      )}

      {status?.status === "failed" && (
        <div className="mb-6 border border-red-900 bg-red-950/30 rounded p-3 text-sm text-red-200">
          Ingest failed: {status.error}
        </div>
      )}

      {status?.status === "ready" && (
        <div className="mb-6 flex items-center gap-3 text-xs text-neutral-500">
          <span>
            {status.csv_counts?.assets} assets · {status.csv_counts?.vulnerabilities} vulns ·{" "}
            {status.kev_records} KEV records · {status.nist_chunks} NIST controls embedded
          </span>
          <button
            onClick={refresh}
            disabled={refreshing}
            className="px-2 py-1 border border-neutral-700 rounded hover:bg-neutral-800 disabled:opacity-50"
          >
            {refreshing ? "Refreshing…" : "Refresh data"}
          </button>
        </div>
      )}

      {error && <p className="mb-4 text-sm text-amber-400">{error}</p>}
      {loadingRisks && <p className="mb-4 text-sm text-neutral-500">Scoring and retrieving guidance…</p>}

      <div className="space-y-4 mb-12">
        {risks.map((r, i) => (
          <article key={r.risk_id} className="border border-neutral-800 rounded-lg p-4 bg-neutral-900">
            <div className="flex justify-between items-baseline gap-4">
              <h2 className="font-semibold text-lg">
                {i + 1}. {r.vulnerability_name}
              </h2>
              <span className="text-sm text-neutral-400 shrink-0">{r.score.toFixed(3)}</span>
            </div>

            <div className="flex flex-wrap gap-1.5 mt-2 mb-3">
              <Chip text={`${ID_LABEL[r.id_type]}: ${r.risk_id}`} />
              {r.cvss !== null && <Chip text={`CVSS ${r.cvss}`} />}
              {r.kev_status === "yes" && <Chip text="Listed in CISA KEV" tone="danger" />}
              {r.kev_status === "unknown" && <Chip text="KEV status unknown" tone="warn" />}
              {r.active_ransomware_campaign && <Chip text="Active ransomware campaign" tone="danger" />}
              {!r.active_ransomware_campaign && r.active_campaign_matched && <Chip text="Active campaign" tone="warn" />}
              {r.kev_ransomware_use && !r.active_ransomware_campaign && (
                <Chip text="CISA: historical ransomware use" tone="warn" />
              )}
              {r.internet_exposed_asset_count > 0 && (
                <Chip
                  text={`Internet-exposed ${r.internet_exposed_asset_count}/${r.asset_count}`}
                  tone="warn"
                />
              )}
              {r.max_criticality && <Chip text={r.max_criticality} />}
            </div>

            <p className="text-sm text-neutral-400 mb-1">
              <span className="text-neutral-500">Business service:</span>{" "}
              {r.business_services.join(", ") || "unmapped"}
            </p>

            <details className="text-sm text-neutral-400 mb-3">
              <summary className="cursor-pointer hover:text-neutral-200">
                {r.asset_count} affected asset{r.asset_count === 1 ? "" : "s"}
              </summary>
              <table className="mt-2 w-full text-xs border-collapse">
                <thead className="text-neutral-500">
                  <tr>
                    <th className="text-left py-1">Asset</th>
                    <th className="text-left py-1">Service</th>
                    <th className="text-left py-1">Exposure</th>
                    <th className="text-right py-1">Score</th>
                  </tr>
                </thead>
                <tbody>
                  {r.affected_assets.map((a) => (
                    <tr key={a.vuln_id} className="border-t border-neutral-800">
                      <td className="py-1">{a.asset_name}</td>
                      <td className="py-1">{a.business_service}</td>
                      <td className="py-1">{a.asset_exposure}</td>
                      <td className="py-1 text-right">{a.score.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>

            <div className="mb-3">
              <p className="text-xs uppercase tracking-wide text-neutral-500 mb-1">
                Why this ranks here
              </p>
              <p className="text-neutral-200">{r.explanation.why_it_ranks}</p>
            </div>

            <div className="mb-3 border-l-2 border-amber-700 pl-3">
              <p className="text-xs uppercase tracking-wide text-amber-600 mb-1">
                Matched threat intel
              </p>
              {r.threat_intel.length === 0 ? (
                <p className="text-sm text-neutral-500">
                  None — ranks on exposure, exploitability and control gaps alone.
                </p>
              ) : (
                r.threat_intel.map((t) => (
                  <div key={t.intel_id} className="mb-2 last:mb-0">
                    <p className="text-sm text-neutral-200">
                      {t.threat_actor} · &ldquo;{t.campaign_name}&rdquo;
                    </p>
                    <p className="text-xs text-neutral-500">
                      {[
                        t.exploit_maturity,
                        t.confidence ? `${t.confidence} confidence` : null,
                        t.ransomware_association ? "ransomware-associated" : null,
                        t.active_last_seen ? `last seen ${t.active_last_seen}` : null,
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </p>
                    {t.summary && <p className="text-sm text-neutral-400 mt-1">{t.summary}</p>}
                  </div>
                ))
              )}
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-neutral-500 mb-1">
                Remediation — NIST SP 800-53 Rev.5{" "}
                {r.nist_control_id ? `${r.nist_control_id} ${r.nist_control_name}` : ""}
                {r.nist_page !== null ? ` (p.${r.nist_page})` : ""}
              </p>
              <p className="text-neutral-200">{r.explanation.remediation}</p>
              {r.explanation.source === "fallback" && (
                <p className="text-xs text-neutral-600 mt-1">
                  Generated from structured data (model unavailable).
                </p>
              )}
            </div>

            {r.nist_control_excerpt && (
              <details className="text-sm text-neutral-500 mt-3">
                <summary className="cursor-pointer hover:text-neutral-300">
                  Retrieved control text
                </summary>
                <p className="mt-2 whitespace-pre-wrap text-xs">{r.nist_control_excerpt}</p>
              </details>
            )}

            {r.alias_names.length > 0 && (
              <p className="text-xs text-neutral-600 mt-3">
                Also reported as: {r.alias_names.join("; ")}
              </p>
            )}
          </article>
        ))}
      </div>

      <section className="border-t border-neutral-800 pt-6">
        <h2 className="font-semibold mb-1">NIST 800-53 retrieval</h2>
        <p className="text-sm text-neutral-500 mb-3">
          Query the embedded control catalogue directly — the same retrieval path the report uses.
        </p>
        <div className="flex gap-2 mb-4">
          <input
            className="flex-1 bg-neutral-900 border border-neutral-700 rounded px-3 py-2"
            placeholder="e.g. unsupported components no longer receiving security updates"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && searchNist()}
          />
          <button
            onClick={searchNist}
            disabled={searching}
            className="px-4 py-2 bg-neutral-700 rounded hover:bg-neutral-600 disabled:opacity-50"
          >
            {searching ? "Searching…" : "Search"}
          </button>
        </div>
        {searchError && <p className="text-sm text-amber-400 mb-3">{searchError}</p>}
        <div className="space-y-3">
          {nistHits.map((h, i) => (
            <div key={i} className="text-sm border border-neutral-800 rounded p-3">
              <p className="text-neutral-300 mb-1">
                {h.control_id} {h.control_name}
                <span className="text-neutral-600">
                  {" "}
                  · p.{h.page} · distance {h.distance.toFixed(3)}
                </span>
              </p>
              <p className="whitespace-pre-wrap text-neutral-400 text-xs">{h.text}</p>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
