"use client";

import { useMemo, useState } from "react";
import type { SecuritySummary } from "@/types";

interface Props { summary: SecuritySummary | null | undefined; onRefresh?: () => void; }

const severityClass: Record<string, string> = {
  CRITICAL: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  HIGH: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  MEDIUM: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  LOW: "border-slate-600 bg-slate-800/60 text-slate-300",
  UNKNOWN: "border-slate-600 bg-slate-800/60 text-slate-400",
};

const layerClass: Record<string, string> = {
  "CONTROL PLANE": "bg-violet-500/10 text-violet-300 border-violet-500/20",
  DATASTORE: "bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/20",
  NETWORK: "bg-cyan-500/10 text-cyan-300 border-cyan-500/20",
  WORKLOAD: "bg-blue-500/10 text-blue-300 border-blue-500/20",
  RUNTIME: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20",
  COMPLIANCE: "bg-indigo-500/10 text-indigo-300 border-indigo-500/20",
  SCANNER: "bg-slate-800 text-slate-400 border-slate-700",
};

function Provider({ name, state, detail, tone }: { name: string; state: string; detail: string; tone: string }) {
  return <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
    <div className="flex items-center justify-between gap-2"><span className="text-sm font-semibold text-slate-200">{name}</span><span className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${tone}`}>{state}</span></div>
    <p className="mt-2 text-[11px] leading-5 text-slate-500">{detail}</p>
  </div>;
}

export default function SecuritySummary({ summary, onRefresh }: Props) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const issues = useMemo(() => (summary?.priority_issues || []).slice(0, 10).map((issue, index) => ({ ...issue, rank: index + 1 })), [summary]);

  if (!summary) return null;
  if (summary.status === "UNAVAILABLE") return <section className="rounded-2xl border border-rose-700/30 bg-slate-900/70 p-6 shadow-lg"><h2 className="text-lg font-semibold text-rose-300">Security scan unavailable</h2><p className="mt-2 text-sm text-slate-300">{summary.reason || "Security evidence could not be collected."}</p></section>;

  const critical = issues.filter(i => i.severity === "CRITICAL").length;
  const high = issues.filter(i => i.severity === "HIGH").length;
  const medium = issues.filter(i => i.severity === "MEDIUM").length;
  const low = issues.filter(i => i.severity === "LOW" || i.severity === "UNKNOWN").length;
  const coverage = summary.coverage || {};
  const source = summary.source_status || {};
  const toggle = (id: string) => setExpanded(v => ({ ...v, [id]: !v[id] }));
  const totalResources = summary.affected_workloads ?? 0;
  const totalNamespaces = summary.affected_namespaces ?? 0;

  return <section className="overflow-hidden rounded-2xl border border-slate-700/40 bg-slate-900/80 shadow-2xl backdrop-blur">
    <div className="border-b border-slate-700/40 bg-gradient-to-br from-slate-900 via-slate-900 to-indigo-950/30 px-5 py-6 sm:px-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex items-center gap-3"><span className="inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-xl text-cyan-300">◈</span><div><h2 className="text-xl font-semibold text-slate-100">Security Posture</h2><p className="text-sm text-slate-400">Verified findings, live providers, and affected resources</p></div></div>
          <p className="mt-4 text-xs text-slate-500">No composite risk score. Severity is determined by the security impact of the finding.</p>
        </div>
        {onRefresh && <button onClick={onRefresh} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800">Refresh security evidence</button>}
      </div>

      <div className="mt-5 grid grid-cols-2 gap-3 md:grid-cols-5">
        {[['CRITICAL', critical, 'border-rose-500/20 bg-rose-500/5 text-rose-300'], ['HIGH', high, 'border-orange-500/20 bg-orange-500/5 text-orange-300'], ['MEDIUM', medium, 'border-amber-500/20 bg-amber-500/5 text-amber-300'], ['LOW', low, 'border-slate-700/50 bg-slate-950/50 text-slate-400'], ['UNIQUE ISSUES', summary.total_unique_issues ?? issues.length, 'border-slate-700/50 bg-slate-950/50 text-slate-400']].map(([label, value, cls]) => <div key={String(label)} className={`rounded-xl border p-3 ${cls}`}><p className="text-[10px] uppercase tracking-wider">{label}</p><p className="mt-1 text-2xl font-bold text-slate-100">{value}</p></div>)}
      </div>

      <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
        <div className="rounded-xl border border-slate-700/50 bg-slate-950/50 p-3"><p className="text-[10px] uppercase tracking-wider text-slate-500">Affected resources</p><p className="mt-1 text-xl font-bold text-slate-100">{totalResources}</p></div>
        <div className="rounded-xl border border-slate-700/50 bg-slate-950/50 p-3"><p className="text-[10px] uppercase tracking-wider text-slate-500">Affected namespaces</p><p className="mt-1 text-xl font-bold text-slate-100">{totalNamespaces}</p></div>
        <div className="rounded-xl border border-slate-700/50 bg-slate-950/50 p-3"><p className="text-[10px] uppercase tracking-wider text-slate-500">Vulnerabilities</p><p className="mt-1 text-xl font-bold text-slate-100">{summary.total_vulnerabilities ?? 0}</p></div>
        <div className="rounded-xl border border-slate-700/50 bg-slate-950/50 p-3"><p className="text-[10px] uppercase tracking-wider text-slate-500">Exposed secrets</p><p className="mt-1 text-xl font-bold text-slate-100">{summary.total_exposed_secrets ?? 0}</p></div>
      </div>

      <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/45 p-4">
        <div className="mb-3 flex items-center justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Security providers</p><p className="mt-1 text-xs text-slate-600">Each provider answers a different security question.</p></div></div>
        <div className="grid gap-3 md:grid-cols-3">
          <Provider name="Trivy" state="CONNECTED" detail={`${summary.total_vulnerabilities ?? 0} vulnerability findings · image/configuration evidence`} tone="bg-cyan-500/10 text-cyan-300" />
          <Provider name="Kubescape" state={source.kubescape?.installed ? "LIVE" : "NOT DETECTED"} detail={source.kubescape?.installed ? `${source.kubescape.failed_controls ?? 0} failed controls · Kubernetes posture` : "Install the Kubescape operator to collect posture evidence."} tone={source.kubescape?.installed ? "bg-indigo-500/10 text-indigo-300" : "bg-slate-800 text-slate-500"} />
          <Provider name="Falco" state={source.falco?.installed ? "LIVE" : "NOT DETECTED"} detail={source.falco?.installed ? `${source.falco.alerts ?? 0} recent runtime alerts · refresh after an exec/event` : "Install Falco on Linux nodes for runtime detection."} tone={source.falco?.installed ? "bg-emerald-500/10 text-emerald-300" : "bg-slate-800 text-slate-500"} />
        </div>
      </div>

      <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/45 p-4">
        <div className="mb-3 flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Security layers checked</p><p className="text-[10px] text-slate-600">finding count, not a score</p></div>
        <div className="space-y-2">{['CONTROL PLANE','DATASTORE','WORKLOAD','NETWORK','RUNTIME','COMPLIANCE'].map(label => { const count = Number(coverage[label] || 0); return <div key={label} className="flex items-center gap-3"><span className={`w-32 rounded-md border px-2.5 py-1 text-[10px] font-bold ${layerClass[label] || layerClass.SCANNER}`}>{label}</span><div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full bg-slate-500" style={{ width: `${count ? Math.min(100, Math.max(6, count * 8)) : 0}%` }} /></div><span className="w-8 text-right font-mono text-[10px] text-slate-500">{count}</span></div>; })}</div>
      </div>
    </div>

    <div className="px-4 py-5 sm:px-6">
      <div className="mb-4 flex items-end justify-between"><div><h3 className="text-sm font-semibold uppercase tracking-widest text-slate-300">Immediate attention</h3><p className="mt-1 text-xs text-slate-500">Top 10 by severity. Open a card for proof, scope, and fix.</p></div><span className="rounded-full bg-slate-800 px-2.5 py-1 text-[10px] font-semibold text-slate-500">10 max</span></div>
      {issues.length === 0 ? <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6"><p className="font-semibold text-emerald-300">No verified security issues were found.</p></div> : <div className="space-y-3">{issues.map(issue => { const open = expanded[issue.id] ?? issue.rank === 1; return <article key={issue.id} className="overflow-hidden rounded-xl border border-slate-700/50 bg-slate-950/60">
        <button onClick={() => toggle(issue.id)} className="flex w-full items-center gap-3 px-4 py-4 text-left hover:bg-slate-900/80 sm:px-5">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-900 text-sm font-bold text-slate-300">{issue.rank}</span>
          <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-1.5"><span className={`rounded-md border px-2 py-1 text-[10px] font-bold ${severityClass[issue.severity] || severityClass.UNKNOWN}`}>{issue.severity}</span><span className={`rounded-md border px-2 py-1 text-[10px] font-semibold ${layerClass[issue.layer] || layerClass.SCANNER}`}>{issue.layer}</span><span className="rounded-md bg-slate-800 px-2 py-1 text-[10px] text-slate-500">{issue.source}</span>{issue.cve && <span className="font-mono text-[10px] text-slate-600">{issue.cve}</span>}</div><h4 className="mt-2 font-semibold leading-5 text-slate-100">{issue.title}</h4><p className="mt-1 truncate font-mono text-xs text-cyan-300/80">{issue.affected_resources?.[0] || 'cluster'}{issue.affected_count > 1 ? ` + ${issue.affected_count - 1} more resources` : ''}</p></div>
          <span className="shrink-0 text-slate-500">{open ? '▲' : '▼'}</span>
        </button>
        {open && <div className="grid gap-3 border-t border-slate-800/80 px-4 py-4 sm:grid-cols-3 sm:px-5"><div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Why it matters</p><p className="mt-1.5 text-sm leading-6 text-slate-300">{issue.why}</p></div><div className="rounded-xl border border-cyan-500/10 bg-cyan-500/5 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-cyan-300">Proof</p><p className="mt-1.5 break-words font-mono text-xs leading-5 text-cyan-200">{issue.evidence}</p><p className="mt-2 text-[10px] text-slate-600">Affected resources: {issue.affected_count}</p></div><div className="rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300">Recommended fix</p><p className="mt-1.5 text-sm leading-6 text-slate-300">{issue.fix}</p><p className="mt-3 text-[10px] font-semibold uppercase tracking-wider text-slate-600">Verify</p><p className="mt-1 text-xs leading-5 text-slate-500">{issue.verify}</p></div></div>}
      </article>; })}</div>}
    </div>
  </section>;
}
