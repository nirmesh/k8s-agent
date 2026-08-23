"use client";

import { useMemo, useState } from "react";
import type { SecurityIssue, SecuritySummary } from "@/types";

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
    default: return "bg-slate-800 text-slate-400 border-slate-700";
  }
}

function scoreClass(score: number) {
  return score >= 90 ? "text-rose-300" : score >= 75 ? "text-orange-300" : "text-amber-300";
}

export default function SecuritySummary({ summary }: Props) {
  const [visible, setVisible] = useState(10);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const issues = useMemo(() => {
    const raw = summary?.priority_issues || [];
    return raw.map((issue, index) => ({ ...issue, rank: index + 1 }));
  }, [summary]);

  if (!summary) return null;
  if (summary.status === "UNAVAILABLE") {
    return (
      <section className="rounded-2xl border border-rose-700/30 bg-slate-900/70 p-6 shadow-lg">
        <h2 className="text-lg font-semibold text-rose-300">Security scan unavailable</h2>
        <p className="mt-2 text-sm text-slate-300">{summary.reason || "Security evidence could not be collected."}</p>
      </section>
    );
  }

  const critical = issues.filter((i) => i.severity === "CRITICAL").length;
  const high = issues.filter((i) => i.severity === "HIGH").length;
  const coverage = summary.coverage || {};
  const coverageItems = [
    ["CONTROL PLANE", coverage["CONTROL PLANE"] || 0],
    ["DATASTORE", coverage.DATASTORE || 0],
    ["WORKLOAD", coverage.WORKLOAD || 0],
    ["NETWORK", coverage.NETWORK || 0],
    ["SCANNER", coverage.SCANNER || 0],
  ];

  const toggle = (id: string) => setExpanded((current) => ({ ...current, [id]: !current[id] }));

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-700/40 bg-slate-900/70 shadow-xl backdrop-blur">
      <div className="border-b border-slate-700/30 px-6 py-6">
        <div className="flex items-start justify-between gap-5">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-rose-500/10 text-rose-300">◆</span>
              <div>
                <h2 className="text-xl font-semibold text-slate-100">Security Findings</h2>
                <p className="mt-0.5 text-sm text-slate-400">Top risks to fix first — across the whole Kubernetes stack</p>
              </div>
            </div>
            <div className="mt-3 flex items-center gap-2 text-xs text-slate-500">
              <span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-slate-600 text-[10px] font-bold">i</span>
              <span>Verified configuration/scanner evidence. Duplicate CVEs are aggregated instead of repeated.</span>
            </div>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Posture</p>
            <p className={`text-3xl font-bold ${summary.cluster_security_score !== null && summary.cluster_security_score < 50 ? "text-rose-300" : "text-amber-300"}`}>
              {summary.cluster_security_score ?? "—"}
            </p>
            <p className="text-[10px] text-slate-600">/100</p>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4">
            <p className="text-[11px] uppercase tracking-wider text-rose-300">Critical in top list</p>
            <p className="mt-1 text-2xl font-bold text-slate-100">{critical}</p>
          </div>
          <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
            <p className="text-[11px] uppercase tracking-wider text-orange-300">High in top list</p>
            <p className="mt-1 text-2xl font-bold text-slate-100">{high}</p>
          </div>
          <div className="rounded-xl border border-slate-700/40 bg-slate-950/50 p-4">
            <p className="text-[11px] uppercase tracking-wider text-slate-500">Unique issues</p>
            <p className="mt-1 text-2xl font-bold text-slate-100">{summary.total_unique_issues ?? issues.length}</p>
          </div>
          <div className="rounded-xl border border-slate-700/40 bg-slate-950/50 p-4">
            <p className="text-[11px] uppercase tracking-wider text-slate-500">Affected workloads</p>
            <p className="mt-1 text-2xl font-bold text-slate-100">{summary.affected_workloads ?? 0}</p>
          </div>
        </div>

        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <div className="mb-2 flex items-center justify-between">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Coverage</p>
            <p className="text-[10px] text-slate-600">what was actually checked</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {coverageItems.map(([label, count]) => (
              <span key={String(label)} className={`rounded-md border px-2.5 py-1 text-[10px] font-semibold ${layerClass(String(label))}`}>
                {label} · {count}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="px-4 py-5 sm:px-6">
        <div className="mb-3 flex items-end justify-between">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">Immediate attention</h3>
            <p className="mt-1 text-xs text-slate-500">One row = one distinct issue. Open it for proof and the two-line fix.</p>
          </div>
          <span className="text-xs text-slate-600">Showing {Math.min(visible, issues.length)} of {issues.length}</span>
        </div>

        {issues.length === 0 ? (
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6">
            <p className="font-semibold text-emerald-300">No verified security issues were found.</p>
            <p className="mt-1 text-sm text-slate-400">Nothing is fabricated to fill the dashboard. Add the demo fixtures if you want to exercise remediation scenarios.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {issues.slice(0, visible).map((issue) => {
              const isOpen = expanded[issue.id] ?? issue.rank === 1;
              return (
                <article key={issue.id} className="overflow-hidden rounded-xl border border-slate-700/40 bg-slate-950/55">
                  <button onClick={() => toggle(issue.id)} className="flex w-full items-center gap-3 px-4 py-4 text-left transition-colors hover:bg-slate-900 sm:gap-4 sm:px-5">
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-slate-800 text-sm font-bold text-slate-300">{issue.rank}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className={`rounded-md border px-2 py-1 text-[10px] font-bold tracking-wide ${severityClass(issue.severity)}`}>{issue.severity}</span>
                        <span className={`rounded-md border px-2 py-1 text-[10px] font-semibold ${layerClass(issue.layer)}`}>{issue.layer}</span>
                        <span className="rounded-md bg-slate-800 px-2 py-1 text-[10px] text-slate-500">{issue.category.replaceAll("_", " ")}</span>
                        {issue.cve && <span className="font-mono text-[10px] text-slate-600">{issue.cve}</span>}
                      </div>
                      <h4 className="mt-2 font-semibold leading-5 text-slate-100">{issue.title}</h4>
                      <p className="mt-1 truncate font-mono text-xs text-cyan-300/80">{issue.affected_resources?.[0] || "cluster"}{issue.affected_count > 1 ? ` + ${issue.affected_count - 1} more` : ""}</p>
                    </div>
                    <div className="hidden shrink-0 text-right sm:block">
                      <p className="text-[10px] uppercase tracking-wider text-slate-600">Priority</p>
                      <p className={`text-xl font-bold ${scoreClass(issue.score)}`}>{issue.score}</p>
                    </div>
                    <span className="shrink-0 text-slate-500">{isOpen ? "▲" : "▼"}</span>
                  </button>

                  {isOpen && (
                    <div className="grid gap-3 border-t border-slate-800/80 px-4 py-4 sm:grid-cols-3 sm:px-5">
                      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Why critical</p>
                        <p className="mt-1.5 text-sm leading-6 text-slate-300">{issue.why}</p>
                      </div>
                      <div className="rounded-lg border border-cyan-500/10 bg-cyan-500/5 p-3">
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-cyan-300">Proof</p>
                        <p className="mt-1.5 break-words font-mono text-xs leading-5 text-cyan-200">{issue.evidence}</p>
                        {issue.occurrences > 1 && <p className="mt-2 text-[10px] text-slate-600">Observed {issue.occurrences} times across {issue.affected_count} resource(s).</p>}
                      </div>
                      <div className="rounded-lg border border-emerald-500/10 bg-emerald-500/5 p-3">
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300">Fix in 2 steps</p>
                        <p className="mt-1.5 text-sm leading-5 text-slate-300"><span className="font-semibold text-slate-200">1.</span> {issue.fix}</p>
                        <p className="mt-2 text-sm leading-5 text-slate-400"><span className="font-semibold text-slate-300">2.</span> {issue.verify}</p>
                      </div>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}

        {issues.length > visible && (
          <button onClick={() => setVisible((v) => Math.min(v + 10, issues.length))} className="mt-4 w-full rounded-xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm font-semibold text-slate-300 transition-colors hover:border-cyan-500/40 hover:text-cyan-300">
            Show 10 more issues
          </button>
        )}
      </div>

      <div className="border-t border-slate-700/30 px-6 py-3 text-xs text-slate-600">
        Priority combines severity and observed context. It does not claim that an issue has been exploited.
      </div>
    </section>
  );
}
