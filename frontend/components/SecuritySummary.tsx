"use client";

import { useMemo, useState } from "react";
import type { SecuritySummary } from "@/types";

interface Props { summary: SecuritySummary | null | undefined; }

function severityClass(severity: string) {
  switch (severity.toUpperCase()) {
    case "CRITICAL": return "border-rose-500/30 bg-rose-500/10 text-rose-300";
    case "HIGH": return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    case "MEDIUM": return "border-amber-500/30 bg-amber-500/10 text-amber-300";
    default: return "border-slate-600 bg-slate-800/60 text-slate-300";
  }
}

function layerClass(layer: string) {
  switch (layer) {
    case "CONTROL PLANE": return "bg-violet-500/10 text-violet-300 border-violet-500/20";
    case "DATASTORE": return "bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/20";
    case "NETWORK": return "bg-cyan-500/10 text-cyan-300 border-cyan-500/20";
    case "WORKLOAD": return "bg-blue-500/10 text-blue-300 border-blue-500/20";
    case "RUNTIME": return "bg-emerald-500/10 text-emerald-300 border-emerald-500/20";
    case "COMPLIANCE": return "bg-indigo-500/10 text-indigo-300 border-indigo-500/20";
    case "SCANNER": return "bg-slate-800 text-slate-400 border-slate-700";
    default: return "bg-slate-800 text-slate-400 border-slate-700";
  }
}

function scoreClass(score: number) {
  return score < 50 ? "text-rose-300" : score < 75 ? "text-orange-300" : score < 90 ? "text-amber-300" : "text-emerald-300";
}

function scoreLabel(score: number) {
  return score < 50 ? "Needs immediate attention" : score < 75 ? "High risk" : score < 90 ? "Needs hardening" : "Healthy";
}

export default function SecuritySummary({ summary }: Props) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showScoreDetails, setShowScoreDetails] = useState(true);
  const issues = useMemo(() => (summary?.priority_issues || []).slice(0, 10).map((issue, index) => ({ ...issue, rank: index + 1 })), [summary]);

  if (!summary) return null;
  if (summary.status === "UNAVAILABLE") {
    return <section className="rounded-2xl border border-rose-700/30 bg-slate-900/70 p-6 shadow-lg"><h2 className="text-lg font-semibold text-rose-300">Security scan unavailable</h2><p className="mt-2 text-sm text-slate-300">{summary.reason || "Security evidence could not be collected."}</p></section>;
  }

  const score = summary.cluster_security_score ?? 0;
  const critical = issues.filter((i) => i.severity === "CRITICAL").length;
  const high = issues.filter((i) => i.severity === "HIGH").length;
  const coverage = summary.coverage || {};
  const layers = [
    ["CONTROL PLANE", coverage["CONTROL PLANE"] || 0],
    ["DATASTORE", coverage.DATASTORE || 0],
    ["WORKLOAD", coverage.WORKLOAD || 0],
    ["NETWORK", coverage.NETWORK || 0],
    ["RUNTIME", coverage.RUNTIME || 0],
    ["COMPLIANCE", coverage.COMPLIANCE || 0],
    ["SCANNER", coverage.SCANNER || 0],
  ] as const;
  const sourceStatus = summary.source_status || {};
  const maxPoints = Math.max(1, ...(summary.score_breakdown || []).map((item) => Number(item.points) || 0));
  const toggle = (id: string) => setExpanded((current) => ({ ...current, [id]: !current[id] }));

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-700/40 bg-slate-900/80 shadow-2xl backdrop-blur">
      <div className="border-b border-slate-700/40 bg-gradient-to-br from-slate-900 via-slate-900 to-indigo-950/30 px-5 py-6 sm:px-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <span className="inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-xl text-cyan-300">◈</span>
              <div><h2 className="text-xl font-semibold text-slate-100">Security Posture</h2><p className="mt-0.5 text-sm text-slate-400">The 10 issues that deserve attention first</p></div>
            </div>
            <div className="mt-4 flex items-center gap-2 text-xs text-slate-500"><span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-slate-600 text-[10px] font-bold">i</span><span>Evidence first — no unverified attack claims. One card represents one distinct issue.</span></div>
          </div>

          <div className="flex items-center gap-4 rounded-2xl border border-slate-700/50 bg-slate-950/60 px-4 py-3">
            <div className="relative h-20 w-20 shrink-0 rounded-full p-1" style={{ background: `conic-gradient(from 225deg, currentColor ${Math.max(0, Math.min(100, score)) * 2.7}deg, rgba(51,65,85,.35) 0deg)`, color: "rgb(34 211 238)" }}>
              <div className="flex h-full w-full items-center justify-center rounded-full bg-slate-950"><span className={`text-2xl font-bold ${scoreClass(score)}`}>{score}</span></div>
            </div>
            <div><p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Cluster score</p><p className={`mt-1 text-sm font-semibold ${scoreClass(score)}`}>{scoreLabel(score)}</p><p className="mt-1 text-[11px] text-slate-600">/ 100 · verified posture</p></div>
          </div>
        </div>

        <div className="mt-5 rounded-2xl border border-slate-700/50 bg-slate-950/55">
          <button onClick={() => setShowScoreDetails((v) => !v)} className="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-slate-900/70">
            <div><p className="text-xs font-semibold uppercase tracking-wider text-slate-300">Why this score?</p><p className="mt-0.5 text-xs text-slate-500">See exactly what pushed the rating down.</p></div><span className="text-slate-500">{showScoreDetails ? "▲" : "▼"}</span>
          </button>
          {showScoreDetails && <div className="border-t border-slate-800/80 px-4 py-4">
            <p className="text-sm leading-6 text-slate-300">{summary.score_explanation || summary.score_basis || "Score is based on verified security evidence."}</p>
            <div className="mt-4 space-y-3">
              {(summary.score_breakdown || []).map((item) => {
                const width = Math.max(2, Math.min(100, ((Number(item.points) || 0) / maxPoints) * 100));
                return <div key={item.label}><div className="mb-1 flex items-center justify-between gap-3 text-xs"><span className="text-slate-400">{item.label}</span><span className="font-mono text-slate-500">{Number(item.points).toFixed(Number(item.points) % 1 ? 1 : 0)} pts · {item.detail}</span></div><div className="h-2 overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full bg-gradient-to-r from-indigo-500 via-cyan-400 to-rose-400" style={{ width: `${width}%` }} /></div></div>;
              })}
            </div>
            <p className="mt-4 text-[11px] leading-5 text-slate-600">The score is a prioritization aid. It is not a probability that the cluster has been compromised.</p>
          </div>}
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-3"><p className="text-[10px] uppercase tracking-wider text-rose-300">Critical</p><p className="mt-1 text-2xl font-bold text-slate-100">{critical}</p></div>
          <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-3"><p className="text-[10px] uppercase tracking-wider text-orange-300">High</p><p className="mt-1 text-2xl font-bold text-slate-100">{high}</p></div>
          <div className="rounded-xl border border-slate-700/50 bg-slate-950/50 p-3"><p className="text-[10px] uppercase tracking-wider text-slate-500">Unique issues</p><p className="mt-1 text-2xl font-bold text-slate-100">{summary.total_unique_issues ?? issues.length}</p></div>
          <div className="rounded-xl border border-slate-700/50 bg-slate-950/50 p-3"><p className="text-[10px] uppercase tracking-wider text-slate-500">Affected resources</p><p className="mt-1 text-2xl font-bold text-slate-100">{summary.affected_workloads ?? 0}</p></div>
        </div>

        <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/45 p-3">
          <div className="mb-3 flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Security layers checked</p><p className="text-[10px] text-slate-600">breadth before depth</p></div>
          <div className="space-y-2">
            {layers.map(([label, count]) => <div key={label} className="flex items-center gap-3"><span className={`w-32 rounded-md border px-2.5 py-1 text-[10px] font-bold ${layerClass(label)}`}>{label}</span><div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full bg-slate-500" style={{ width: `${Math.min(100, Number(count) * 12)}%` }} /></div><span className="w-8 text-right font-mono text-[10px] text-slate-500">{count}</span></div>)}
          </div>
          <div className="mt-3 flex flex-wrap gap-2 border-t border-slate-800 pt-3">
            <span className={`rounded-md border px-2 py-1 text-[10px] ${sourceStatus.kubescape?.installed ? "border-indigo-500/20 bg-indigo-500/10 text-indigo-300" : "border-slate-700 text-slate-600"}`}>Kubescape {sourceStatus.kubescape?.installed ? `· ${sourceStatus.kubescape.failed_controls} failed` : "· not detected"}</span>
            <span className={`rounded-md border px-2 py-1 text-[10px] ${sourceStatus.falco?.installed ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-300" : "border-slate-700 text-slate-600"}`}>Falco {sourceStatus.falco?.installed ? `· ${sourceStatus.falco.alerts} recent alerts` : "· not detected"}</span>
            <span className="rounded-md border border-slate-700 px-2 py-1 text-[10px] text-slate-500">Trivy · prioritized only</span>
          </div>
        </div>
      </div>

      <div className="px-4 py-5 sm:px-6">
        <div className="mb-4 flex items-end justify-between"><div><h3 className="text-sm font-semibold uppercase tracking-widest text-slate-300">Immediate attention</h3><p className="mt-1 text-xs text-slate-500">Top 10 only. Open a card for proof, impact and a two-step fix.</p></div><span className="rounded-full bg-slate-800 px-2.5 py-1 text-[10px] font-semibold text-slate-500">10 max</span></div>

        {issues.length === 0 ? <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6"><p className="font-semibold text-emerald-300">No verified security issues were found.</p><p className="mt-1 text-sm text-slate-400">Nothing is fabricated to fill the dashboard.</p></div> : <div className="space-y-3">
          {issues.map((issue) => {
            const isOpen = expanded[issue.id] ?? issue.rank === 1;
            return <article key={issue.id} className="overflow-hidden rounded-xl border border-slate-700/50 bg-slate-950/60 shadow-lg shadow-black/10">
              <button onClick={() => toggle(issue.id)} className="flex w-full items-center gap-3 px-4 py-4 text-left transition-colors hover:bg-slate-900/80 sm:gap-4 sm:px-5">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-900 text-sm font-bold text-slate-300">{issue.rank}</span>
                <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-1.5"><span className={`rounded-md border px-2 py-1 text-[10px] font-bold tracking-wide ${severityClass(issue.severity)}`}>{issue.severity}</span><span className={`rounded-md border px-2 py-1 text-[10px] font-semibold ${layerClass(issue.layer)}`}>{issue.layer}</span><span className="rounded-md bg-slate-800 px-2 py-1 text-[10px] text-slate-500">{issue.source}</span>{issue.cve && <span className="font-mono text-[10px] text-slate-600">{issue.cve}</span>}</div><h4 className="mt-2 font-semibold leading-5 text-slate-100">{issue.title}</h4><p className="mt-1 truncate font-mono text-xs text-cyan-300/80">{issue.affected_resources?.[0] || "cluster"}{issue.affected_count > 1 ? ` + ${issue.affected_count - 1} more` : ""}</p></div>
                <div className="hidden shrink-0 text-right sm:block"><p className="text-[10px] uppercase tracking-wider text-slate-600">Risk</p><p className={`text-xl font-bold ${scoreClass(issue.score)}`}>{issue.score}</p></div><span className="shrink-0 text-slate-500">{isOpen ? "▲" : "▼"}</span>
              </button>
              {isOpen && <div className="grid gap-3 border-t border-slate-800/80 px-4 py-4 sm:grid-cols-3 sm:px-5"><div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Why it matters</p><p className="mt-1.5 text-sm leading-6 text-slate-300">{issue.why}</p></div><div className="rounded-xl border border-cyan-500/10 bg-cyan-500/5 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-cyan-300">Proof</p><p className="mt-1.5 break-words font-mono text-xs leading-5 text-cyan-200">{issue.evidence}</p>{issue.occurrences > 1 && <p className="mt-2 text-[10px] text-slate-600">Observed {issue.occurrences} times across {issue.affected_count} resource(s). Aggregated.</p>}</div><div className="rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300">Fix in 2 steps</p><p className="mt-1.5 text-sm leading-5 text-slate-300"><span className="font-semibold text-slate-200">1.</span> {issue.fix}</p><p className="mt-2 text-sm leading-5 text-slate-400"><span className="font-semibold text-slate-300">2.</span> {issue.verify}</p></div></div>}
            </article>;
          })}
        </div>}
      </div>
      <div className="border-t border-slate-700/30 px-6 py-3 text-xs text-slate-600">The list is deliberately bounded to the ten most actionable distinct issues. Full scanner output is not the product surface.</div>
    </section>
  );
}
