"use client";

import { useState } from "react";
import type { SecuritySummary } from "@/types";

interface Props {
  summary: SecuritySummary | null | undefined;
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function SecuritySummary({ summary }: Props) {
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  if (!summary) return null;

  if (summary.status === "UNAVAILABLE") {
    return (
      <section className="rounded-2xl border border-rose-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur">
        <h2 className="text-lg font-semibold text-rose-300">Security Data Unavailable</h2>
        <p className="mt-2 text-sm text-slate-300">
          {summary.reason || "Security evidence could not be collected from the cluster."}
        </p>
      </section>
    );
  }

  const rawScore = summary.cluster_security_score;
  const score = rawScore ?? null;
  const scoreLabel = score === null ? "UNKNOWN" : `${score}/100`;
  const scoreColor =
    score === null
      ? "text-slate-400"
      : score >= 80
      ? "text-emerald-400"
      : score >= 50
      ? "text-amber-400"
      : "text-rose-400";

  const toggle = (idx: number) => {
    setExpanded((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const top = summary.top_10_risks || [];
  const workloadCount = summary.affected_workloads ?? summary.workload_count ?? 0;

  return (
    <section className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Security Findings</h2>
          <p className="text-sm text-slate-400">Prioritized by workload, not raw CVEs.</p>
          {summary.score_basis && (
            <p className="mt-1 max-w-2xl text-xs text-slate-500">Score: {summary.score_basis}</p>
          )}
        </div>
        <div className="text-right">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Cluster Score</p>
          <p className={`text-3xl font-bold ${scoreColor}`}>{scoreLabel}</p>
        </div>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">Vulnerabilities</p>
          <p className="text-xl font-semibold text-slate-100">{summary.total_vulnerabilities ?? 0}</p>
        </div>
        <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">Misconfigs</p>
          <p className="text-xl font-semibold text-slate-100">{summary.total_misconfigurations ?? 0}</p>
        </div>
        <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">Exposed Secrets</p>
          <p className="text-xl font-semibold text-slate-100">{summary.total_exposed_secrets ?? 0}</p>
        </div>
        <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">Workloads</p>
          <p className="text-xl font-semibold text-slate-100">{workloadCount}</p>
        </div>
      </div>

      <div className="mb-6 grid grid-cols-3 gap-4 md:grid-cols-6">
        <div className="rounded-lg border border-slate-700/30 bg-slate-950/50 p-3 text-center">
          <p className="text-[10px] uppercase tracking-wider text-rose-400">Critical</p>
          <p className="text-lg font-semibold text-slate-100">{summary.critical_vulnerabilities ?? 0}</p>
        </div>
        <div className="rounded-lg border border-slate-700/30 bg-slate-950/50 p-3 text-center">
          <p className="text-[10px] uppercase tracking-wider text-orange-400">High</p>
          <p className="text-lg font-semibold text-slate-100">{summary.high_vulnerabilities ?? 0}</p>
        </div>
        <div className="rounded-lg border border-slate-700/30 bg-slate-950/50 p-3 text-center">
          <p className="text-[10px] uppercase tracking-wider text-amber-400">Medium</p>
          <p className="text-lg font-semibold text-slate-100">{summary.medium_vulnerabilities ?? 0}</p>
        </div>
        <div className="rounded-lg border border-slate-700/30 bg-slate-950/50 p-3 text-center">
          <p className="text-[10px] uppercase tracking-wider text-emerald-400">Low</p>
          <p className="text-lg font-semibold text-slate-100">{summary.low_vulnerabilities ?? 0}</p>
        </div>
        <div className="rounded-lg border border-slate-700/30 bg-slate-950/50 p-3 text-center">
          <p className="text-[10px] uppercase tracking-wider text-slate-400">Unknown</p>
          <p className="text-lg font-semibold text-slate-100">{summary.unknown_vulnerabilities ?? 0}</p>
          <p className="mt-1 text-[10px] text-slate-600">not scored</p>
        </div>
        <div className="rounded-lg border border-slate-700/30 bg-slate-950/50 p-3 text-center">
          <p className="text-[10px] uppercase tracking-wider text-slate-400">Namespaces</p>
          <p className="text-lg font-semibold text-slate-100">{summary.affected_namespaces ?? 0}</p>
        </div>
      </div>

      {summary.top_recommendations && summary.top_recommendations.length > 0 && (
        <div className="mb-6 rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">Top Recommendations</p>
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
            {summary.top_recommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ul>
        </div>
      )}

      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-500">Top Risky Workloads</h3>
      <div className="space-y-3">
        {top.length === 0 ? (
          <p className="text-sm text-slate-500">No security findings collected.</p>
        ) : (
          top.map((w, idx) => {
            const isOpen = expanded[idx];
            const total = SEVERITY_ORDER.reduce((acc, s) => acc + (w.counts?.[s] || 0), 0);
            return (
              <div key={idx} className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
                <button onClick={() => toggle(idx)} className="flex w-full items-center justify-between text-left">
                  <div>
                    <p className="font-medium text-slate-100">{w.namespace}/{w.name}</p>
                    <p className="text-xs text-slate-400">{total} findings · {w.recommendation}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="flex gap-2">
                      {SEVERITY_ORDER.map((s) =>
                        w.counts?.[s] ? (
                          <span key={s} className={`rounded-full px-2 py-0.5 text-xs font-semibold ${s === "CRITICAL" ? "bg-rose-500/20 text-rose-300" : s === "HIGH" ? "bg-orange-500/20 text-orange-300" : s === "MEDIUM" ? "bg-amber-500/20 text-amber-300" : "bg-emerald-500/20 text-emerald-300"}`}>
                            {s}: {w.counts[s]}
                          </span>
                        ) : null
                      )}
                    </div>
                    <span className="rounded-full bg-slate-800 px-2.5 py-1 text-xs font-semibold text-slate-300">{w.risk_score}</span>
                    <span className="text-slate-400">{isOpen ? "▲" : "▼"}</span>
                  </div>
                </button>

                {isOpen && (
                  <div className="mt-4 space-y-2 border-t border-slate-700/30 pt-3">
                    {w.findings && w.findings.length > 0 ? (
                      <ul className="space-y-2">
                        {w.findings.slice(0, 20).map((f, i) => (
                          <li key={i} className="text-sm text-slate-300">
                            <span className={`mr-2 rounded px-1.5 py-0.5 text-xs font-semibold ${f.severity === "CRITICAL" ? "bg-rose-500/20 text-rose-300" : f.severity === "HIGH" ? "bg-orange-500/20 text-orange-300" : f.severity === "MEDIUM" ? "bg-amber-500/20 text-amber-300" : "bg-emerald-500/20 text-emerald-300"}`}>
                              {f.severity}
                            </span>
                            {f.category === "vulnerability" && f.cve_id ? <span className="mr-2 font-mono text-slate-400">{f.cve_id}</span> : null}
                            {f.title}
                            {f.recommendation ? <p className="mt-1 text-xs text-slate-500">{f.recommendation}</p> : null}
                          </li>
                        ))}
                        {w.findings.length > 20 && <li className="text-xs text-slate-500">... {w.findings.length - 20} more findings</li>}
                      </ul>
                    ) : (
                      <p className="text-sm text-slate-500">No individual findings available.</p>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
