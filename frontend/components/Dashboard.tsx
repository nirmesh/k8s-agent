"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import apiClient from "@/services/api";
import MetricsPanel from "@/components/MetricsPanel";
import RemediationPanel from "@/components/RemediationPanel";
import SecuritySummary from "@/components/SecuritySummary";
import ThemeToggle from "@/components/ThemeToggle";
import type { Cluster, Investigation } from "@/types";

function FixDisplay({ fix }: { fix: string }) {
  try {
    const parsed = JSON.parse(fix);
    if (Array.isArray(parsed)) {
      return (
        <ol className="list-decimal space-y-3 pl-5 marker:text-slate-500">
          {parsed.map((item, i) => (
            <li key={i}>
              <span className="font-medium text-slate-200">
                {typeof item.step === "string" ? item.step : String(item.step)}
              </span>
              {item.description && (
                <p className="mt-1 text-sm leading-relaxed text-slate-400">
                  {typeof item.description === "string"
                    ? item.description
                    : String(item.description)}
                </p>
              )}
            </li>
          ))}
        </ol>
      );
    }
  } catch {}
  return <p className="whitespace-pre-wrap text-slate-300">{fix}</p>;
}

const ALL_STEPS = [
  "Checking Pods",
  "Reading Logs",
  "Analyzing Events",
  "Inspecting Deployments",
  "Checking Networking",
  "AI Reasoning",
  "Root Cause Found",
];

const INVESTIGATION_POLL_MS = 2000;
const INVESTIGATION_MAX_MS = 5 * 60 * 1000;
const MAX_CONSECUTIVE_POLL_ERRORS = 5;

type DiagnosisFinding = {
  incident_type?: string;
  root_cause?: string;
  explanation?: string;
  confidence?: number;
  affected_resources?: string[];
  evidence_ids?: string[];
};

function formatIncidentType(value?: string) {
  if (!value) return "Operational incident";
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function resourceKind(resource: string) {
  return resource.split("/")[0] || "Resource";
}

function DiagnosisFindings({ diagnosis }: { diagnosis: Investigation["diagnosis"] }) {
  const findings = ((diagnosis as any)?.findings || []) as DiagnosisFinding[];

  if (findings.length === 0) {
    return (
      <div className="rounded-xl border border-slate-700 bg-slate-950/60 p-5">
        <p className="text-sm text-slate-400">{diagnosis?.root_cause || "No verified operational issue was found."}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Verified findings</p>
          <p className="mt-1 text-sm text-slate-400">
            Each incident is shown separately so unrelated failures are easy to distinguish.
          </p>
        </div>
        <span className="rounded-full border border-rose-400/20 bg-rose-400/10 px-3 py-1 text-sm font-semibold text-rose-200">
          {findings.length} {findings.length === 1 ? "incident" : "incidents"}
        </span>
      </div>

      <div className="space-y-3">
        {findings.map((finding, index) => {
          const confidence = Math.round((Number(finding.confidence) || 0) * 100);
          const resources = finding.affected_resources || [];
          return (
            <article
              key={`${finding.incident_type || "finding"}-${index}`}
              className="overflow-hidden rounded-xl border border-slate-700/80 bg-slate-950/70"
            >
              <div className="flex flex-col gap-3 border-b border-slate-700/70 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex min-w-0 items-center gap-3">
                  <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-rose-500/15 text-sm font-bold text-rose-300">
                    {index + 1}
                  </span>
                  <div className="min-w-0">
                    <h3 className="font-semibold text-slate-100">
                      {formatIncidentType(finding.incident_type)}
                    </h3>
                    <p className="mt-0.5 text-xs text-slate-500">Independently verified finding</p>
                  </div>
                </div>
                <span className="w-fit rounded-full bg-blue-500/15 px-3 py-1 text-xs font-semibold text-blue-300">
                  {confidence}% confidence
                </span>
              </div>

              <div className="space-y-4 px-5 py-4">
                {resources.length > 0 && (
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Affected resource</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {resources.map((resource) => (
                        <span
                          key={resource}
                          className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-xs text-cyan-200"
                        >
                          <span className="rounded bg-slate-800 px-1.5 py-0.5 font-sans text-[10px] text-slate-400">{resourceKind(resource)}</span>
                          <span className="break-all">{resource}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Root cause</p>
                  <p className="mt-1 text-sm font-medium leading-6 text-slate-200">{finding.root_cause || "No root cause description provided."}</p>
                </div>

                {finding.explanation && (
                  <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-3">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Why it is happening</p>
                    <p className="mt-1 text-sm leading-6 text-slate-400">{finding.explanation}</p>
                  </div>
                )}

                {finding.evidence_ids && finding.evidence_ids.length > 0 && (
                  <p className="text-xs text-slate-600">
                    {finding.evidence_ids.length} verified evidence {finding.evidence_ids.length === 1 ? "item" : "items"}
                  </p>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const router = useRouter();
  const [history, setHistory] = useState<Investigation[]>([]);
  const [current, setCurrent] = useState<Investigation | null>(null);
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [selectedContext, setSelectedContext] = useState("");
  const [loadingClusters, setLoadingClusters] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [error, setError] = useState("");
  const investigationPollRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const investigationStartedAtRef = useRef<number | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    fetchHistory();
    fetchClusters();
    return () => {
      if (investigationPollRef.current) {
        clearTimeout(investigationPollRef.current);
        investigationPollRef.current = null;
      }
    };
  }, [router]);

  const fetchHistory = async () => {
    try {
      const res = await apiClient.get("/investigations");
      setHistory(res.data.investigations || []);
    } catch (err: any) {
      if (err.response?.status === 401) router.push("/login");
    }
  };

  const fetchClusters = async () => {
    try {
      const res = await apiClient.get("/clusters");
      const list: Cluster[] = res.data.clusters || [];
      setClusters(list);
      const current = list.find((c) => c.current);
      if (current) setSelectedContext(current.name);
    } catch (err: any) {
      if (err.response?.status === 401) router.push("/login");
    } finally {
      setLoadingClusters(false);
    }
  };

  const fetchCurrent = async (id: string) => {
    try {
      const r = await apiClient.get(`/investigations/${id}`);
      setCurrent(r.data.investigation);
      return true;
    } catch (err: any) {
      if (err.response?.status === 401) router.push("/login");
      return false;
    }
  };

  useEffect(() => {
    if (!current?.id || !current.remediation_status) return;
    if (current.remediation_status !== "EXECUTING" && current.remediation_status !== "VERIFYING") return;
    const id = current.id;
    const interval = setInterval(() => fetchCurrent(id), 2000);
    return () => clearInterval(interval);
  }, [current?.id, current?.remediation_status]);

  const startInvestigation = async () => {
    if (investigationPollRef.current) {
      clearTimeout(investigationPollRef.current);
      investigationPollRef.current = null;
    }

    setInvestigating(true);
    setCurrent(null);
    setError("");
    investigationStartedAtRef.current = Date.now();

    try {
      const res = await apiClient.post("/investigate", { context: selectedContext });
      const id = res.data.investigation_id;
      let consecutiveErrors = 0;

      const poll = async () => {
        const startedAt = investigationStartedAtRef.current || Date.now();
        if (Date.now() - startedAt > INVESTIGATION_MAX_MS) {
          setInvestigating(false);
          setError("Investigation is taking longer than expected. The run may still be processing; refresh to check the latest result.");
          return;
        }

        try {
          const r = await apiClient.get(`/investigations/${id}`);
          consecutiveErrors = 0;
          const inv: Investigation = r.data.investigation;
          setCurrent(inv);
          setError("");

          if (inv.status === "completed" || inv.status === "failed") {
            setInvestigating(false);
            investigationPollRef.current = null;
            if (inv.status === "failed") {
              setError(inv.remediation_error || "Investigation failed. Check backend logs for details.");
            }
            fetchHistory();
            return;
          }
        } catch (e: any) {
          consecutiveErrors += 1;
          if (consecutiveErrors >= MAX_CONSECUTIVE_POLL_ERRORS) {
            setInvestigating(false);
            investigationPollRef.current = null;
            setError("Unable to refresh investigation status after several retries. The investigation may still be running; refresh the page to check its latest status.");
            return;
          }
        }

        investigationPollRef.current = setTimeout(poll, INVESTIGATION_POLL_MS);
      };

      await poll();
    } catch (err: any) {
      setInvestigating(false);
      investigationPollRef.current = null;
      setError(err.response?.data?.detail || "Investigation failed to start");
    }
  };

  const logout = () => {
    localStorage.removeItem("token");
    router.push("/login");
  };

  return (
    <div className="min-h-screen bg-slate-50 p-4 text-slate-900 antialiased md:p-8 dark:bg-slate-950 dark:text-slate-100">
      <div className="mx-auto max-w-4xl space-y-6">
        <header className="flex items-center justify-between rounded-2xl border border-slate-700/30 bg-slate-900/60 px-6 py-4 shadow-lg backdrop-blur">
          <div className="flex flex-col">
            <h1 className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-2xl font-bold text-transparent md:text-3xl">AI Kubernetes Agent</h1>
            <span className="text-xs italic text-slate-400">No grepping at 2 am</span>
          </div>
          <div className="flex items-center gap-2"><ThemeToggle /><button onClick={logout} className="rounded-lg px-3 py-2 text-sm font-medium text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100">Log out</button></div>
        </header>

        {loadingClusters ? (
          <div className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 text-center text-slate-400 shadow-lg backdrop-blur">Loading clusters...</div>
        ) : clusters.length === 0 ? (
          <div className="rounded-2xl border border-red-500/30 bg-red-900/20 p-6 text-red-200 shadow-lg backdrop-blur">No Kubernetes clusters found. Check your kubeconfig.</div>
        ) : (
          <section className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur"><label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">Select Cluster</label><select value={selectedContext} onChange={(e) => setSelectedContext(e.target.value)} className="mt-3 w-full rounded-xl border border-slate-600 bg-slate-950 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500">{clusters.map((c) => <option key={c.name} value={c.name} className="bg-slate-950 text-slate-100">{c.name} — {c.server || c.cluster_name}</option>)}</select></section>
        )}

        <button onClick={startInvestigation} disabled={investigating || loadingClusters || clusters.length === 0} className="w-full rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-3.5 text-center font-semibold text-white shadow-lg shadow-cyan-900/20 transition-all hover:from-cyan-400 hover:to-blue-500 hover:shadow-xl disabled:cursor-not-allowed disabled:opacity-50">{investigating ? "Investigating..." : "Investigate Cluster"}</button>
        {error && <div className="rounded-2xl border border-red-500/30 bg-red-900/20 p-4 text-sm text-red-200">{error}</div>}

        {current && (
          <section className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur"><h2 className="mb-4 text-lg font-semibold text-slate-100">Investigation Status</h2><ul className="space-y-3">{(() => { const reported = new Set(current.steps.map((s) => s.name)); const highestCompleted = ALL_STEPS.reduce((max, step, idx) => reported.has(step) ? idx : max, -1); const completedIndex = investigating ? highestCompleted : ALL_STEPS.length - 1; const completed = new Set(ALL_STEPS.slice(0, completedIndex + 1)); const activeIndex = investigating ? Math.min(completedIndex + 1, ALL_STEPS.length - 1) : -1; return ALL_STEPS.map((step, index) => { const isCompleted = completed.has(step); const isActive = index === activeIndex && !isCompleted; return <li key={step} className={isCompleted ? "flex items-center gap-4 rounded-xl bg-emerald-500/10 px-4 py-3 text-emerald-100" : isActive ? "flex items-center gap-4 rounded-xl bg-blue-500/10 px-4 py-3 text-blue-200" : "flex items-center gap-4 rounded-xl px-4 py-3 text-slate-500"}><span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-slate-700 bg-slate-950 text-xs font-semibold">{isCompleted ? <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg> : isActive ? <svg className="h-4 w-4 animate-spin text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg> : index + 1}</span><span className="font-medium">{step}</span></li>; }); })()}</ul></section>
        )}

        {current?.security_summary && <SecuritySummary summary={current.security_summary} />}
        {current?.diagnosis && (
          <section className="overflow-hidden rounded-2xl border border-slate-700/30 bg-slate-900/60 shadow-lg backdrop-blur"><div className="flex items-center justify-between border-b border-slate-700/30 bg-gradient-to-r from-rose-500/10 to-orange-500/10 px-6 py-4"><div className="flex items-center gap-3"><svg className="h-6 w-6 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg><div className="flex flex-col"><h2 className="text-lg font-semibold text-slate-100">Diagnosis</h2><span className="text-xs text-slate-500">Cluster-wide operational findings</span></div></div><span className="rounded-full bg-blue-500/20 px-3 py-1 text-sm font-semibold text-blue-300">{Math.round((current.diagnosis.confidence || 0) * 100)}% confidence</span></div><div className="space-y-6 p-6"><DiagnosisFindings diagnosis={current.diagnosis} /><div><p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Suggested Fix</p><div className="mt-2 text-slate-300"><FixDisplay fix={current.diagnosis.fix} /></div></div><RemediationPanel remediationId={current.remediation_id} investigation={current} onUpdate={setCurrent} /><div><p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Kubectl Command</p><div className="mt-2 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 font-mono text-sm text-emerald-400">{current.diagnosis.kubectl_command || "No command suggested."}</div></div><div><p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Prevention</p><p className="mt-1 leading-relaxed text-slate-300">{current.diagnosis.prevention}</p></div></div></section>
        )}

        <section className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur"><h2 className="mb-4 text-lg font-semibold text-slate-100">Recent Investigations</h2>{history.length === 0 ? <p className="text-slate-500">No investigations yet.</p> : <ul className="space-y-3">{history.map((inv) => <li key={inv.id} className="flex items-start justify-between rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"><div><p className="font-medium text-slate-100">{inv.root_cause || inv.status}</p><p className="mt-1 text-xs text-slate-500">{new Date(inv.created_at).toLocaleString()}</p></div><span className="shrink-0 rounded-full bg-blue-500/20 px-2.5 py-1 text-xs font-semibold text-blue-300">{Math.round((inv.confidence || 0) * 100)}%</span></li>)}</ul>}</section>
        <MetricsPanel />
      </div>
    </div>
  );
}
