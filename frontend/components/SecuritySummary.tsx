"use client";

import { useState } from "react";
import type { SecuritySummary as SecuritySummaryType } from "@/types";

interface Props { summary: SecuritySummaryType | null | undefined; }
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const severityClass = (severity: string) => {
  switch (severity) {
    case "CRITICAL": return "bg-rose-500/20 text-rose-300";
    case "HIGH": return "bg-orange-500/20 text-orange-300";
    case "MEDIUM": return "bg-amber-500/20 text-amber-300";
    default: return "bg-emerald-500/20 text-emerald-300";
  }
};

const infoContent: Record<string, { title: string; text: string }> = {
  posture: {
    title: "What is Native Kubernetes Posture?",
    text: "Read-only checks against the live Kubernetes API. These checks identify risky configuration such as privileged containers, host access, excessive capabilities and weak workload security settings. Severity describes potential security impact; Impact explains what could happen if the condition is abused."
  },
  privileged: {
    title: "Why is privileged dangerous?",
    text: "A privileged container receives substantially elevated Linux privileges and can access host-level resources. If an application workload is compromised, this can increase the chance and impact of container escape or node compromise. Some infrastructure components legitimately require elevated access, so context matters."
  }
};

function InfoTip({ kind, label = "Security information" }: { kind: string; label?: string }) {
  const [open, setOpen] = useState(false);
  const content = infoContent[kind] || infoContent.posture;
  return (
    <span className="relative inline-flex" onClick={(e) => e.stopPropagation()}>
      <button
        type="button"
        aria-label={label}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-slate-600 bg-slate-900 text-[11px] font-bold text-slate-400 transition-colors hover:border-cyan-400 hover:text-cyan-300"
      >
        i
      </button>
      {open && (
        <div className="absolute left-0 top-7 z-30 w-80 rounded-xl border border-slate-600/70 bg-slate-950 p-4 text-left shadow-2xl">
          <p className="text-xs font-semibold text-slate-200">{content.title}</p>
          <p className="mt-2 text-xs leading-5 text-slate-400">{content.text}</p>
        </div>
      )}
    </span>
  );
}

export default function SecuritySummary({ summary }: Props) {
  const [expandedSection, setExpandedSection] = useState(false);
  const [expandedWorkloads, setExpandedWorkloads] = useState<Record<number, boolean>>({});
  const [expandedPosture, setExpandedPosture] = useState<Record<number, boolean>>({});

  if (!summary) return null;
  if (summary.status === "UNAVAILABLE") {
    return (
      <section className="rounded-2xl border border-rose-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur">
        <h2 className="text-lg font-semibold text-rose-300">Security Data Unavailable</h2>
        <p className="mt-2 text-sm text-slate-300">{summary.reason || "Security evidence could not be collected from the cluster."}</p>
      </section>
    );
  }

  const score = summary.cluster_security_score ?? null;
  const scoreLabel = score === null ? "UNKNOWN" : `${score}/100`;
  const scoreColor = score === null ? "text-slate-400" : score >= 80 ? "text-emerald-400" : score >= 50 ? "text-amber-400" : "text-rose-400";
  const toggleWorkload = (idx: number) => setExpandedWorkloads((prev) => ({ ...prev, [idx]: !prev[idx] }));
  const togglePosture = (idx: number) => setExpandedPosture((prev) => ({ ...prev, [idx]: !prev[idx] }));
  const top = summary.top_10_risks || [];
  const workloadCount = summary.affected_workloads ?? summary.workload_count ?? 0;
  const nativePosture = summary.native_posture_findings || [];

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-700/30 bg-slate-900/60 shadow-lg backdrop-blur">
      <button
        onClick={() => setExpandedSection((v) => !v)}
        className="flex w-full items-center justify-between gap-4 px-6 py-5 text-left transition-colors hover:bg-slate-800/30"
        aria-expanded={expandedSection}
      >
        <div className="min-w-0">
          <div className="flex items-center gap-3">
            <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-rose-500/10 text-rose-300">◆</span>
            <div>
              <h2 className="text-lg font-semibold text-slate-100">Security Findings</h2>
              <p className="text-sm text-slate-400">Risk-prioritized security posture</p>
            </div>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-4">
          <div className="text-right">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Cluster Score</p>
            <p className={`text-2xl font-bold ${scoreColor}`}>{scoreLabel}</p>
          </div>
          <span className="text-slate-400">{expandedSection ? "▲" : "▼"}</span>
        </div>
      </button>

      {!expandedSection && (
        <div className="flex flex-wrap items-center gap-2 border-t border-slate-700/20 px-6 py-3 text-xs text-slate-500">
          <span>{summary.total_vulnerabilities ?? 0} vulnerabilities</span><span>·</span>
          <span>{summary.total_misconfigurations ?? 0} misconfigs</span><span>·</span>
          <span>{nativePosture.length} native posture findings</span><span>·</span>
          <span>{workloadCount} workloads</span>
          <span className="ml-auto text-slate-600">Expand for details</span>
        </div>
      )}

      {expandedSection && (
        <div className="border-t border-slate-700/20 p-6">
          {summary.score_basis && <p className="mb-5 max-w-3xl text-xs leading-5 text-slate-500">Score: {summary.score_basis}</p>}

          <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
            <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Vulnerabilities</p><p className="text-xl font-semibold text-slate-100">{summary.total_vulnerabilities ?? 0}</p></div>
            <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Misconfigs</p><p className="text-xl font-semibold text-slate-100">{summary.total_misconfigurations ?? 0}</p></div>
            <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Native Posture</p><p className="text-xl font-semibold text-slate-100">{nativePosture.length}</p></div>
            <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Workloads</p><p className="text-xl font-semibold text-slate-100">{workloadCount}</p></div>
          </div>

          <div className="mb-6 grid grid-cols-3 gap-4 md:grid-cols-6">
            {[['Critical', summary.critical_vulnerabilities ?? 0, 'text-rose-400'], ['High', summary.high_vulnerabilities ?? 0, 'text-orange-400'], ['Medium', summary.medium_vulnerabilities ?? 0, 'text-amber-400'], ['Low', summary.low_vulnerabilities ?? 0, 'text-emerald-400'], ['Unknown', summary.unknown_vulnerabilities ?? 0, 'text-slate-400'], ['Namespaces', summary.affected_namespaces ?? 0, 'text-slate-400']].map(([label, value, color]) => (
              <div key={String(label)} className="rounded-lg border border-slate-700/30 bg-slate-950/50 p-3 text-center">
                <p className={`text-[10px] uppercase tracking-wider ${color}`}>{label}</p><p className="text-lg font-semibold text-slate-100">{value}</p>
                {label === "Unknown" && <p className="mt-1 text-[10px] text-slate-600">not scored</p>}
              </div>
            ))}
          </div>

          {summary.top_recommendations?.length > 0 && <div className="mb-6 rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"><p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">Top Recommendations</p><ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">{summary.top_recommendations.map((rec, i) => <li key={i}>{rec}</li>)}</ul></div>}

          {nativePosture.length > 0 && (
            <div className="mb-6 rounded-xl border border-cyan-500/20 bg-cyan-950/10 p-4">
              <div className="mb-4 flex items-center justify-between gap-3">
                <div className="flex items-start gap-2">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Native Kubernetes Posture</p>
                    <p className="mt-1 text-xs text-slate-500">Read-only checks against the live Kubernetes API</p>
                  </div>
                  <InfoTip kind="posture" label="About native Kubernetes posture" />
                </div>
                <span className="rounded-full bg-cyan-500/10 px-2.5 py-1 text-xs font-semibold text-cyan-300">{nativePosture.length} finding{nativePosture.length === 1 ? "" : "s"}</span>
              </div>
              <div className="space-y-3">
                {nativePosture.map((finding, i) => {
                  const isOpen = expandedPosture[i];
                  const isPrivileged = finding.title?.toLowerCase().includes("privileged");
                  return (
                    <div key={`${finding.resource}-${finding.rule_id || finding.title || i}`} className="rounded-xl border border-slate-700/40 bg-slate-950/60">
                      <button type="button" onClick={() => togglePosture(i)} className="flex w-full items-start justify-between gap-4 p-4 text-left transition-colors hover:bg-slate-900/60" aria-expanded={isOpen}>
                        <div className="min-w-0">
                          <div className="mb-1 flex flex-wrap items-center gap-2">
                            <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${severityClass(finding.severity)}`}>{finding.severity}</span>
                            <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">{finding.layer || "posture"}</span>
                            <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">{finding.domain || "workload"}</span>
                          </div>
                          <p className="font-medium text-slate-100">{finding.title || "Security posture finding"}</p>
                          <p className="mt-1 break-all font-mono text-xs text-cyan-300">{finding.resource}</p>
                        </div>
                        <span className="shrink-0 pt-1 text-slate-400">{isOpen ? "▲" : "▼"}</span>
                      </button>
                      {isOpen && <div className="border-t border-slate-700/40 px-4 pb-4">
                        {finding.description && <p className="mt-3 text-sm leading-5 text-slate-400">{finding.description}</p>}
                        {finding.impact && <p className="mt-2 text-xs leading-5 text-slate-500"><span className="font-semibold text-slate-400">Impact:</span> {finding.impact}</p>}
                        {finding.recommendation && <p className="mt-2 text-xs leading-5 text-slate-500"><span className="font-semibold text-slate-400">Recommendation:</span> {finding.recommendation}</p>}
                        {isPrivileged && <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3"><InfoTip kind="privileged" label="Why privileged containers matter" /><p className="text-xs leading-5 text-slate-400"><span className="font-semibold text-amber-300">Context:</span> Privileged access is powerful and should be reviewed, but infrastructure components such as GPU, storage and networking operators may legitimately require it.</p></div>}
                      </div>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-500">Top Risky Workloads</h3>
          <div className="space-y-3">
            {top.length === 0 ? <p className="text-sm text-slate-500">No security findings collected.</p> : top.map((w, idx) => {
              const isOpen = expandedWorkloads[idx];
              const total = SEVERITY_ORDER.reduce((acc, s) => acc + (w.counts?.[s] || 0), 0);
              return (
                <div key={idx} className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
                  <button onClick={() => toggleWorkload(idx)} className="flex w-full items-center justify-between text-left" aria-expanded={isOpen}>
                    <div><p className="font-medium text-slate-100">{w.namespace}/{w.name}</p><p className="text-xs text-slate-400">{total} findings · {w.recommendation}</p></div>
                    <div className="flex items-center gap-3"><div className="flex gap-2">{SEVERITY_ORDER.map((s) => w.counts?.[s] ? <span key={s} className={`rounded-full px-2 py-0.5 text-xs font-semibold ${s === "CRITICAL" ? "bg-rose-500/20 text-rose-300" : s === "HIGH" ? "bg-orange-500/20 text-orange-300" : s === "MEDIUM" ? "bg-amber-500/20 text-amber-300" : "bg-emerald-500/20 text-emerald-300"}`}>{s}: {w.counts[s]}</span> : null)}</div><span className="rounded-full bg-slate-800 px-2.5 py-1 text-xs font-semibold text-slate-300">{w.risk_score}</span><span className="text-slate-400">{isOpen ? "▲" : "▼"}</span></div>
                  </button>
                  {isOpen && <div className="mt-4 space-y-2 border-t border-slate-700/30 pt-3">{w.findings?.length ? <ul className="space-y-2">{w.findings.slice(0, 20).map((f, i) => <li key={i} className="text-sm text-slate-300"><span className={`mr-2 rounded px-1.5 py-0.5 text-xs font-semibold ${severityClass(f.severity)}`}>{f.severity}</span>{f.category === "vulnerability" && f.cve_id ? <span className="mr-2 font-mono text-slate-400">{f.cve_id}</span> : null}{f.title}{f.recommendation ? <p className="mt-1 text-xs text-slate-500">{f.recommendation}</p> : null}</li>)}{w.findings.length > 20 && <li className="text-xs text-slate-500">... {w.findings.length - 20} more findings</li>}</ul> : <p className="text-sm text-slate-500">No individual findings available.</p>}</div>}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}
