"use client";

import { useMemo, useState } from "react";
import type { SecuritySummary } from "@/types";
import apiClient from "@/services/api";

interface Props { summary: SecuritySummary | null | undefined; }

const severityClass: Record<string, string> = {
  CRITICAL: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  HIGH: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  MEDIUM: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  LOW: "border-slate-700 bg-slate-800/60 text-slate-300",
  UNKNOWN: "border-slate-700 bg-slate-800/60 text-slate-400",
};
const layerClass: Record<string, string> = {
  "CONTROL PLANE": "bg-violet-500/10 text-violet-300 border-violet-500/20",
  DATASTORE: "bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/20",
  NETWORK: "bg-cyan-500/10 text-cyan-300 border-cyan-500/20",
  WORKLOAD: "bg-blue-500/10 text-blue-300 border-blue-500/20",
  RUNTIME: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20",
  COMPLIANCE: "bg-indigo-500/10 text-indigo-300 border-indigo-500/20",
};

function Provider({ name, value }: { name: string; value: any }) {
  const connected = Boolean(value?.installed);
  const liveMinutes = Math.max(1, Math.round((value?.live_window_seconds ?? 300) / 60));
  const detail = name.toLowerCase() === "falco"
    ? connected ? `${value.alerts ?? 0} live alerts in last ${liveMinutes} min · ${value.pods ?? 0} pod(s)` : (value?.error || "Falco was not detected.")
    : connected ? `${value.findings ?? 0} vulnerability findings` : "Provider was not detected.";
  return <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
    <div className="flex items-center justify-between gap-3">
      <span className="text-sm font-semibold text-slate-200">{name}</span>
      <span className={`rounded-full px-2 py-1 text-[10px] font-bold ${connected ? "bg-emerald-500/10 text-emerald-300" : "bg-slate-800 text-slate-500"}`}>{connected ? "CONNECTED" : "NOT DETECTED"}</span>
    </div>
    <p className="mt-2 text-[11px] leading-5 text-slate-500">{detail}</p>
  </div>;
}

export default function SecuritySummary({ summary }: Props) {
  const [live, setLive] = useState<SecuritySummary | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const data = live || summary;

  const issues = useMemo(() => (data?.priority_issues || []).slice(0, 10).map((x, i) => ({ ...x, rank: i + 1 })), [data]);
  if (!data) return null;
  if (data.status === "UNAVAILABLE") return <section className="rounded-2xl border border-rose-500/30 bg-slate-900/80 p-6"><h2 className="text-lg font-semibold text-rose-300">Security scan unavailable</h2><p className="mt-2 text-sm text-slate-300">{data.reason || "Security evidence could not be collected."}</p></section>;

  const refresh = async () => {
    setRefreshing(true); setError(null);
    try {
      const response = await apiClient.post("/security-scan", {});
      if (!response.data?.security_summary) throw new Error("Security scan returned no summary");
      setLive(response.data.security_summary as SecuritySummary);
    } catch (e: any) {
      setError(String(e?.response?.data?.detail || e?.message || "Live security scan failed"));
    } finally { setRefreshing(false); }
  };

  const counts = {
    CRITICAL: issues.filter(i => i.severity === "CRITICAL").length,
    HIGH: issues.filter(i => i.severity === "HIGH").length,
    MEDIUM: issues.filter(i => i.severity === "MEDIUM").length,
    LOW: issues.filter(i => i.severity === "LOW" || i.severity === "UNKNOWN").length,
  };
  const providers = Object.entries(data.source_status || {}).filter(([name]) => name !== "kubescape");
  const coverage = data.coverage || {};

  return <section className="overflow-hidden rounded-2xl border border-slate-700/40 bg-slate-900/80 shadow-2xl backdrop-blur">
    <div className="border-b border-slate-700/40 bg-gradient-to-br from-slate-900 via-slate-900 to-indigo-950/30 px-5 py-6 sm:px-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">Security Posture</h2>
          <p className="text-sm text-slate-400">Verified findings, live providers, and affected resources</p>
          {data.observed_at && <p className="mt-1 font-mono text-[10px] text-slate-600">snapshot {new Date(data.observed_at).toLocaleTimeString()}</p>}
        </div>
        <button onClick={refresh} disabled={refreshing} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 disabled:opacity-50">{refreshing ? "Refreshing…" : "Refresh live evidence"}</button>
      </div>
      {error && <div className="mt-4 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-xs text-rose-300"><b>Live refresh failed:</b> {error}</div>}

      <div className="mt-5 grid grid-cols-2 gap-3 md:grid-cols-5">
        {[['CRITICAL', counts.CRITICAL, 'border-rose-500/20 bg-rose-500/5 text-rose-300'], ['HIGH', counts.HIGH, 'border-orange-500/20 bg-orange-500/5 text-orange-300'], ['MEDIUM', counts.MEDIUM, 'border-amber-500/20 bg-amber-500/5 text-amber-300'], ['LOW', counts.LOW, 'border-slate-700/50 bg-slate-950/50 text-slate-400'], ['UNIQUE ISSUES', data.total_unique_issues ?? issues.length, 'border-slate-700/50 bg-slate-950/50 text-slate-400']].map(([label, value, cls]) => <div key={String(label)} className={`rounded-xl border p-3 ${cls}`}><p className="text-[10px] uppercase tracking-wider">{label}</p><p className="mt-1 text-2xl font-bold text-slate-100">{value}</p></div>)}
      </div>
      <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
        {[['Affected resources', data.affected_workloads ?? 0], ['Affected namespaces', data.affected_namespaces ?? 0], ['Vulnerabilities', data.total_vulnerabilities ?? 0], ['Exposed secrets', data.total_exposed_secrets ?? 0]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-slate-700/50 bg-slate-950/50 p-3"><p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p><p className="mt-1 text-xl font-bold text-slate-100">{value}</p></div>)}
      </div>

      <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/45 p-4">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Security providers</p>
        <p className="mt-1 text-xs text-slate-600">Provider status comes from live evidence collection.</p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">{providers.map(([name, value]) => <Provider key={name} name={name} value={value} />)}</div>
      </div>

      <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950/45 p-4">
        <div className="mb-3 flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Security layers checked</p><p className="text-[10px] text-slate-600">finding count, not a score</p></div>
        <div className="space-y-2">{Object.entries(coverage).map(([name, value]) => { const n = Number(value || 0); return <div key={name} className="flex items-center gap-3"><span className={`w-32 rounded-md border px-2.5 py-1 text-[10px] font-bold ${layerClass[name] || "bg-slate-800 text-slate-400 border-slate-700"}`}>{name}</span><div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full bg-slate-500" style={{ width: n ? `${Math.min(100, Math.max(6, n * 8))}%` : "0%" }}/></div><span className="w-8 text-right font-mono text-[10px] text-slate-500">{n}</span></div>; })}</div>
      </div>
    </div>

    <div className="px-4 py-5 sm:px-6">
      <div className="mb-4"><h3 className="text-sm font-semibold uppercase tracking-widest text-slate-300">Immediate attention</h3><p className="mt-1 text-xs text-slate-500">Verified evidence first; explanations and remediation are LLM-assisted.</p></div>
      {issues.length === 0 ? <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6"><p className="font-semibold text-emerald-300">No verified security issues were found.</p></div> : <div className="space-y-3">{issues.map(issue => { const open = expanded[issue.id] ?? issue.rank === 1; return <article key={issue.id} className="overflow-hidden rounded-xl border border-slate-700/50 bg-slate-950/60">
        <button onClick={() => setExpanded(v => ({ ...v, [issue.id]: !open }))} className="flex w-full items-center gap-3 px-4 py-4 text-left hover:bg-slate-900/80 sm:px-5"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-900 text-sm font-bold text-slate-300">{issue.rank}</span><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-1.5"><span className={`rounded-md border px-2 py-1 text-[10px] font-bold ${severityClass[issue.severity] || severityClass.UNKNOWN}`}>{issue.severity}</span><span className={`rounded-md border px-2 py-1 text-[10px] font-semibold ${layerClass[issue.layer] || "bg-slate-800 text-slate-400 border-slate-700"}`}>{issue.layer}</span><span className="rounded-md bg-slate-800 px-2 py-1 text-[10px] text-slate-500">{issue.source}</span>{issue.explanation_source === "llm" && <span className="rounded-md border border-cyan-500/15 bg-cyan-500/5 px-2 py-1 text-[10px] font-semibold text-cyan-300">AI explained</span>}</div><h4 className="mt-2 font-semibold leading-5 text-slate-100">{issue.title}</h4><p className="mt-1 truncate font-mono text-xs text-cyan-300/80">{issue.affected_resources?.[0] || "cluster"}{issue.affected_count > 1 ? ` + ${issue.affected_count - 1} more resources` : ""}</p></div><span className="shrink-0 text-slate-500">{open ? "▲" : "▼"}</span></button>
        {open && <div className="grid gap-3 border-t border-slate-800/80 px-4 py-4 sm:grid-cols-3 sm:px-5"><div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Why it matters</p><p className="mt-1.5 text-sm leading-6 text-slate-300">{issue.why}</p></div><div className="rounded-xl border border-cyan-500/10 bg-cyan-500/5 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-cyan-300">Verified proof</p><p className="mt-1.5 break-words font-mono text-xs leading-5 text-cyan-200">{issue.evidence}</p></div><div className="rounded-xl border border-emerald-500/10 bg-emerald-500/5 p-4"><p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300">Recommended response</p><p className="mt-1.5 text-sm leading-6 text-slate-300">{issue.fix}</p><p className="mt-3 text-[10px] text-slate-500">Verify: {issue.verify}</p></div></div>}
      </article>; })}</div>}
    </div>
  </section>;
}
