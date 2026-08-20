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

const checkStatusClass = (status: string) => {
  switch (status) {
    case "PASS": return "bg-emerald-500/10 text-emerald-300 border-emerald-500/20";
    case "FAIL": return "bg-rose-500/10 text-rose-300 border-rose-500/20";
    default: return "bg-amber-500/10 text-amber-300 border-amber-500/20";
  }
};

const infoContent: Record<string, { title: string; text: string }> = {
  posture: {
    title: "What is Native Kubernetes Posture?",
    text: "Read-only checks against the live Kubernetes API. These checks identify risky configuration such as privileged containers, host access, excessive capabilities and weak workload security settings. Severity describes potential security impact; Impact explains what could happen if the condition is abused."
  },
  controls: {
    title: "What are control-plane checks?",
    text: "These checks show the security state of important Kubernetes controls even when there is no finding. PASS means the control was positively verified, FAIL means a risky state was verified, and NOT VERIFIED means the application could not prove the configuration from the live API."
  },
  privileged: {
    title: "Why is privileged dangerous?",
    text: "A privileged container receives substantially elevated Linux privileges and can access host-level resources. If an application workload is compromised, this can increase the chance and impact of container escape or node compromise. Some infrastructure components legitimately require elevated access, so context matters."
  },
  scanner: {
    title: "What is scanner evidence?",
    text: "Scanner evidence is supporting data from security tools such as Trivy. It is kept as evidence for deeper investigation and correlation, but it is not the security model by itself."
  }
};

function InfoTip({ kind, label = "Security information" }: { kind: string; label?: string }) {
  const [open, setOpen] = useState(false);
  const content = infoContent[kind] || infoContent.posture;
  return (
    <span className="relative inline-flex shrink-0 self-center" onClick={(e) => e.stopPropagation()}>
      <button type="button" aria-label={label} aria-expanded={open} onClick={() => setOpen((v) => !v)} className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-slate-600 bg-slate-900 text-[11px] font-bold leading-none text-slate-400 transition-colors hover:border-cyan-400 hover:text-cyan-300">i</button>
      {open && <div className="absolute left-0 top-7 z-30 w-80 rounded-xl border border-slate-600/70 bg-slate-950 p-4 text-left shadow-2xl"><p className="text-xs font-semibold text-slate-200">{content.title}</p><p className="mt-2 text-xs leading-5 text-slate-400">{content.text}</p></div>}
    </span>
  );
}

export default function SecuritySummary({ summary }: Props) {
  const [expandedSection, setExpandedSection] = useState(false);
  const [postureOpen, setPostureOpen] = useState(true);
  const [controlsOpen, setControlsOpen] = useState(true);
  const [scannerOpen, setScannerOpen] = useState(false);
  const [workloadsOpen, setWorkloadsOpen] = useState(false);
  const [expandedWorkloads, setExpandedWorkloads] = useState<Record<number, boolean>>({});
  const [expandedPosture, setExpandedPosture] = useState<Record<number, boolean>>({});

  if (!summary) return null;
  if (summary.status === "UNAVAILABLE") {
    return <section className="rounded-2xl border border-rose-700/30 bg-slate-900/60 p-6 shadow-lg"><h2 className="text-lg font-semibold text-rose-300">Security Data Unavailable</h2><p className="mt-2 text-sm text-slate-300">{summary.reason || "Security evidence could not be collected from the cluster."}</p></section>;
  }

  const top = summary.top_10_risks || [];
  const workloadCount = summary.affected_workloads ?? summary.workload_count ?? 0;
  const nativePosture = summary.native_posture_findings || [];
  const postureChecks = summary.native_posture_checks || [];
  const toggleWorkload = (idx: number) => setExpandedWorkloads((prev) => ({ ...prev, [idx]: !prev[idx] }));
  const togglePosture = (idx: number) => setExpandedPosture((prev) => ({ ...prev, [idx]: !prev[idx] }));

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-700/30 bg-slate-900/60 shadow-lg backdrop-blur">
      <button onClick={() => setExpandedSection((v) => !v)} className="flex w-full items-center justify-between gap-4 px-6 py-5 text-left transition-colors hover:bg-slate-800/30" aria-expanded={expandedSection}>
        <div className="flex min-w-0 items-center gap-3"><span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-rose-500/10 text-rose-300">◆</span><div><h2 className="text-lg font-semibold text-slate-100">Security Findings</h2><p className="text-sm text-slate-400">Risk-prioritized security posture</p></div></div>
        <span className="shrink-0 text-slate-400">{expandedSection ? "▲" : "▼"}</span>
      </button>

      {!expandedSection && <div className="flex flex-wrap items-center gap-2 border-t border-slate-700/20 px-6 py-3 text-xs text-slate-500"><span>{nativePosture.length} native posture findings</span><span>·</span><span>{workloadCount} affected workloads</span><span>·</span><span>{postureChecks.length} control checks</span><span className="ml-auto text-slate-600">Expand for details</span></div>}

      {expandedSection && <div className="border-t border-slate-700/20 p-6">
        <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-3">
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/10 p-4"><p className="text-xs uppercase tracking-wider text-cyan-300">Native Posture</p><p className="text-xl font-semibold text-slate-100">{nativePosture.length}</p></div>
          <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Affected Workloads</p><p className="text-xl font-semibold text-slate-100">{workloadCount}</p></div>
          <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Namespaces</p><p className="text-xl font-semibold text-slate-100">{summary.affected_namespaces ?? 0}</p></div>
        </div>

        {postureChecks.length > 0 && <div className="mb-6 overflow-hidden rounded-xl border border-violet-500/20 bg-violet-950/10">
          <button type="button" onClick={() => setControlsOpen((v) => !v)} className="flex w-full items-center justify-between gap-4 p-4 text-left hover:bg-violet-950/20" aria-expanded={controlsOpen}>
            <div className="flex min-w-0 items-center gap-2"><div><p className="text-sm font-semibold uppercase tracking-wider text-violet-300">Control Plane &amp; Datastore</p><p className="mt-1 text-xs text-slate-500">Verified security controls from the live Kubernetes API</p></div><InfoTip kind="controls" label="About control-plane security checks" /></div>
            <div className="flex shrink-0 items-center gap-3"><span className="rounded-full bg-violet-500/10 px-2.5 py-1 text-xs font-semibold text-violet-300">{postureChecks.length} checks</span><span className="text-slate-400">{controlsOpen ? "▲" : "▼"}</span></div>
          </button>
          {controlsOpen && <div className="border-t border-violet-500/10 p-4"><div className="grid gap-2 md:grid-cols-2">
            {postureChecks.map((check) => <div key={check.id} className="rounded-lg border border-slate-700/40 bg-slate-950/60 p-3">
              <div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="text-sm font-medium text-slate-100">{check.title}</p><p className="mt-1 text-xs leading-5 text-slate-500">{check.detail}</p>{check.resource && <p className="mt-1 break-all font-mono text-[10px] text-slate-600">{check.resource}</p>}</div><span className={`shrink-0 rounded-md border px-2 py-1 text-[10px] font-semibold tracking-wide ${checkStatusClass(check.status)}`}>{check.status === "NOT_VERIFIED" ? "NOT VERIFIED" : check.status}</span></div>
              {check.status === "FAIL" && check.recommendation && <p className="mt-2 text-xs text-slate-500"><b className="text-slate-400">Recommendation:</b> {check.recommendation}</p>}
            </div>)}
          </div></div>}
        </div>}

        {nativePosture.length > 0 && <div className="mb-6 overflow-hidden rounded-xl border border-cyan-500/20 bg-cyan-950/10">
          <button type="button" onClick={() => setPostureOpen((v) => !v)} className="flex w-full items-center justify-between gap-4 p-4 text-left hover:bg-cyan-950/20" aria-expanded={postureOpen}>
            <div className="flex min-w-0 items-center gap-2"><div><p className="text-sm font-semibold uppercase tracking-wider text-cyan-300">Native Kubernetes Posture</p><p className="mt-1 text-xs text-slate-500">Read-only checks against the live Kubernetes API</p></div><InfoTip kind="posture" label="About native Kubernetes posture" /></div>
            <div className="flex shrink-0 items-center gap-3"><span className="rounded-full bg-cyan-500/10 px-2.5 py-1 text-xs font-semibold text-cyan-300">{nativePosture.length} finding{nativePosture.length === 1 ? "" : "s"}</span><span className="text-slate-400">{postureOpen ? "▲" : "▼"}</span></div>
          </button>
          {postureOpen && <div className="space-y-3 border-t border-cyan-500/10 p-4">{nativePosture.map((finding, i) => {
            const open = expandedPosture[i];
            const privileged = finding.title?.toLowerCase().includes("privileged");
            return <div key={`${finding.resource}-${finding.rule_id || finding.title || i}`} className="overflow-hidden rounded-xl border border-slate-700/40 bg-slate-950/60">
              <button type="button" onClick={() => togglePosture(i)} className="flex w-full items-start justify-between gap-4 p-4 text-left hover:bg-slate-900/60" aria-expanded={open}>
                <div className="min-w-0"><div className="mb-1 flex flex-wrap items-center gap-2"><span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${severityClass(finding.severity)}`}>{finding.severity}</span><span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">{finding.layer || "posture"}</span><span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-400">{finding.domain || "workload"}</span></div><p className="font-medium text-slate-100">{finding.title || "Security posture finding"}</p><p className="mt-1 break-all font-mono text-xs text-cyan-300">{finding.resource}</p></div>
                <span className="shrink-0 pt-1 text-slate-400">{open ? "▲" : "▼"}</span>
              </button>
              {open && <div className="border-t border-slate-700/40 px-4 pb-4">{finding.description && <p className="mt-3 text-sm leading-5 text-slate-400">{finding.description}</p>}{finding.impact && <p className="mt-2 text-xs leading-5 text-slate-500"><b className="text-slate-400">Impact:</b> {finding.impact}</p>}{finding.recommendation && <p className="mt-2 text-xs leading-5 text-slate-500"><b className="text-slate-400">Recommendation:</b> {finding.recommendation}</p>}{privileged && <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3"><InfoTip kind="privileged" label="Why privileged containers matter" /><p className="text-xs leading-5 text-slate-400"><b className="text-amber-300">Context:</b> Privileged access is powerful and should be reviewed, but infrastructure components such as GPU, storage and networking operators may legitimately require it.</p></div>}</div>}
            </div>;
          })}</div>}
        </div>}

        <div className="mb-6 overflow-hidden rounded-xl border border-slate-700/30 bg-slate-950/40">
          <button type="button" onClick={() => setWorkloadsOpen((v) => !v)} className="flex w-full items-center justify-between gap-4 p-4 text-left hover:bg-slate-900/60" aria-expanded={workloadsOpen}><div><p className="text-sm font-semibold uppercase tracking-wider text-slate-500">Top Risky Workloads</p><p className="mt-1 text-xs text-slate-600">Workloads ranked by collected security risk</p></div><span className="text-slate-400">{workloadsOpen ? "▲" : "▼"}</span></button>
          {workloadsOpen && <div className="space-y-3 border-t border-slate-700/30 p-4">{top.length === 0 ? <p className="text-sm text-slate-500">No security findings collected.</p> : top.map((w, idx) => { const open = expandedWorkloads[idx]; const total = SEVERITY_ORDER.reduce((a, s) => a + (w.counts?.[s] || 0), 0); return <div key={idx} className="rounded-xl border border-slate-700/30 bg-slate-950/60 p-4"><button type="button" onClick={() => toggleWorkload(idx)} className="flex w-full items-center justify-between gap-4 text-left" aria-expanded={open}><div><p className="font-medium text-slate-100">{w.namespace}/{w.name}</p><p className="text-xs text-slate-400">{total} findings · {w.recommendation}</p></div><div className="flex items-center gap-3"><div className="hidden gap-2 md:flex">{SEVERITY_ORDER.map((s) => w.counts?.[s] ? <span key={s} className={`rounded-full px-2 py-0.5 text-xs font-semibold ${severityClass(s)}`}>{s}: {w.counts[s]}</span> : null)}</div><span className="rounded-full bg-slate-800 px-2.5 py-1 text-xs font-semibold text-slate-300">{w.risk_score}</span><span className="text-slate-400">{open ? "▲" : "▼"}</span></div></button>{open && <div className="mt-4 border-t border-slate-700/30 pt-3">{w.findings?.length ? <ul className="space-y-2">{w.findings.slice(0, 20).map((f, i) => <li key={i} className="text-sm text-slate-300"><span className={`mr-2 rounded px-1.5 py-0.5 text-xs font-semibold ${severityClass(f.severity)}`}>{f.severity}</span>{f.category === "vulnerability" && f.cve_id ? <span className="mr-2 font-mono text-slate-400">{f.cve_id}</span> : null}{f.title}{f.recommendation ? <p className="mt-1 text-xs text-slate-500">{f.recommendation}</p> : null}</li>)}{w.findings.length > 20 && <li className="text-xs text-slate-500">... {w.findings.length - 20} more findings</li>}</ul> : <p className="text-sm text-slate-500">No individual findings available.</p>}</div>}</div>; })}</div>}
        </div>

        <div className="overflow-hidden rounded-xl border border-slate-700/30 bg-slate-950/40">
          <button type="button" onClick={() => setScannerOpen((v) => !v)} className="flex w-full items-center justify-between gap-4 p-4 text-left hover:bg-slate-900/60" aria-expanded={scannerOpen}><div className="flex items-center gap-2"><div><p className="text-sm font-semibold uppercase tracking-wider text-slate-500">Scanner Evidence</p><p className="mt-1 text-xs text-slate-600">Supporting evidence from tools such as Trivy; kept secondary to posture and risk context.</p></div><InfoTip kind="scanner" label="About scanner evidence" /></div><span className="text-slate-400">{scannerOpen ? "▲" : "▼"}</span></button>
          {scannerOpen && <div className="border-t border-slate-700/30 p-4"><div className="grid grid-cols-2 gap-4 md:grid-cols-4"><div><p className="text-xs uppercase text-slate-600">Vulnerabilities</p><p className="text-lg text-slate-300">{summary.total_vulnerabilities ?? 0}</p></div><div><p className="text-xs uppercase text-slate-600">Misconfigs</p><p className="text-lg text-slate-300">{summary.total_misconfigurations ?? 0}</p></div><div><p className="text-xs uppercase text-rose-400">Critical</p><p className="text-lg text-slate-300">{summary.critical_vulnerabilities ?? 0}</p></div><div><p className="text-xs uppercase text-orange-400">High</p><p className="text-lg text-slate-300">{summary.high_vulnerabilities ?? 0}</p></div></div></div>}
        </div>
      </div>}
    </section>
  );
}
