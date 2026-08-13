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

type RelatedControl = {
  control_id: string | null;
  control_name: string | null;
  page: number | null;
  distance: number | null;
  confidence: string | null;
};

type CampaignDetail = {
  threat_actor: string | null;
  campaign_name: string | null;
  target_profile: string | null;
  exploit_chain: string | null;
  ransomware: string | null;
  confidence: string | null;
  narrative: string | null;
  iocs: string | null;
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
  kev_date_added: string | null;
  threat_intel_campaign_matched: boolean;
  ransomware_campaign_matched: boolean;
  threat_intel: ThreatIntel[];
  campaign_detail: CampaignDetail | null;
  related_controls: RelatedControl[];
  nist_control_id: string | null;
  nist_control_name: string | null;
  nist_control_excerpt: string | null;
  nist_page: number | null;
  retrieval_distance: number | null;
  retrieval_confidence: string | null;
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
  kev_error?: string | null;
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
        <div className="mb-6 text-xs text-neutral-500">
          {status.csv_counts?.assets} assets · {status.csv_counts?.vulnerabilities} vulns ·{" "}
          {status.kev_records} KEV records · {status.nist_chunks} NIST controls embedded
        </div>
      )}

      {status?.degraded?.includes("kev") && (
        <div className="mb-6 border border-amber-900 bg-amber-950/30 rounded p-3 text-sm text-amber-200">
          Degraded: the CISA KEV catalogue could not be loaded, so exploitation status is unknown
          rather than negative for every finding.
          {status.kev_error ? ` (${status.kev_error})` : ""}
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
              {r.kev_status === "matched" && (
                <Chip text="Actively exploited — CISA KEV" tone="danger" />
              )}
              {r.kev_status === "unavailable" && (
                <Chip text="KEV unavailable — status unknown" tone="warn" />
              )}
              {r.ransomware_campaign_matched && (
                <Chip text="Matched active ransomware campaign" tone="danger" />
              )}
              {!r.ransomware_campaign_matched && r.threat_intel_campaign_matched && (
                <Chip text="Matched active campaign" tone="warn" />
              )}
              {r.kev_ransomware_use && (
                <Chip text="Known ransomware use — CISA historical" tone="warn" />
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
              {r.campaign_detail && (
                <details className="mt-2 text-sm">
                  <summary className="cursor-pointer text-amber-500 hover:text-amber-400">
                    Campaign detail (MDR advisory)
                  </summary>
                  <dl className="mt-2 space-y-1 text-xs text-neutral-400">
                    {r.campaign_detail.exploit_chain && (
                      <div>
                        <dt className="inline text-neutral-500">Exploit chain: </dt>
                        <dd className="inline">{r.campaign_detail.exploit_chain}</dd>
                      </div>
                    )}
                    {r.campaign_detail.ransomware && (
                      <div>
                        <dt className="inline text-neutral-500">Ransomware: </dt>
                        <dd className="inline">{r.campaign_detail.ransomware}</dd>
                      </div>
                    )}
                    {r.campaign_detail.narrative && (
                      <div>
                        <dt className="inline text-neutral-500">Tradecraft: </dt>
                        <dd className="inline">{r.campaign_detail.narrative}</dd>
                      </div>
                    )}
                    {r.campaign_detail.iocs && (
                      <div>
                        <dt className="inline text-neutral-500">IOCs: </dt>
                        <dd className="inline">{r.campaign_detail.iocs}</dd>
                      </div>
                    )}
                  </dl>
                </details>
              )}
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-neutral-500 mb-1">
                Remediation — NIST SP 800-53 Rev.5{" "}
                {r.nist_control_id ? `${r.nist_control_id} ${r.nist_control_name}` : ""}
                {r.nist_page !== null ? ` (p.${r.nist_page})` : ""}
                {r.retrieval_confidence ? ` · ${r.retrieval_confidence} confidence` : ""}
              </p>
              <p className="text-neutral-200">{r.explanation.remediation}</p>
              {r.kev_required_action && (
                <p className="text-sm text-neutral-400 mt-2">
                  <span className="text-neutral-500">CISA KEV required action: </span>
                  {r.kev_required_action}
                </p>
              )}
              {r.related_controls.length > 0 && (
                <p className="text-xs text-neutral-500 mt-2">
                  Related controls:{" "}
                  {r.related_controls
                    .map((c) =>
                      [c.control_id, c.control_name].filter(Boolean).join(" ") +
                      (c.page !== null ? ` (p.${c.page})` : "")
                    )
                    .join("; ")}
                </p>
              )}
              {r.retrieval_confidence === "low" && (
                <p className="text-xs text-amber-500 mt-1">
                  Low-confidence control match — verify before acting.
                </p>
              )}
              {r.explanation.source === "fallback" && (
                <p className="text-xs text-neutral-600 mt-1">
                  Extracted from the retrieved NIST control because the language model was
                  unavailable.
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
