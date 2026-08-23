"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

import apiClient from "@/services/api";
import MetricsPanel from "@/components/MetricsPanel";
import RemediationPanel from "@/components/RemediationPanel";
import SecuritySummary from "@/components/SecuritySummary";
import ThemeToggle from "@/components/ThemeToggle";
import type { Cluster, Investigation } from "@/types";

const POLL_MS = 2000;
const MAX_MS = 5 * 60 * 1000;
const STEPS = ["Security Scan", "Checking Pods", "Reading Logs", "Analyzing Events", "Inspecting Deployments", "Checking Networking", "AI Reasoning", "Root Cause Found"];

type Finding = {
  incident_type?: string;
  root_cause?: string;
  explanation?: string;
  confidence?: number;
  affected_resources?: string[];
  evidence_ids?: string[];
};

function FixDisplay({ fix }: { fix: string }) {
  try {
    const parsed = JSON.parse(fix);
    if (Array.isArray(parsed)) {
      return <ol className="list-decimal space-y-2 pl-5">{parsed.map((item, i) => <li key={i}><span className="font-medium text-slate-200">{String(item.step)}</span>{item.description && <p className="mt-1 text-sm text-slate-400">{String(item.description)}</p>}</li>)}</ol>;
    }
  } catch {}
  return <p className="whitespace-pre-wrap text-slate-300">{fix || "No remediation generated."}</p>;
}

function DiagnosisSection({ investigation, onUpdate }: { investigation: Investigation; onUpdate: (value: Investigation) => void }) {
  const [open, setOpen] = useState(false);
  const findings = (investigation.diagnosis?.findings || []) as Finding[];
  const confidence = Math.round((investigation.diagnosis?.confidence || 0) * 100);

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-700/40 bg-slate-900/70 shadow-xl backdrop-blur">
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center justify-between gap-4 px-6 py-5 text-left hover:bg-slate-800/30">
        <div className="flex items-center gap-3">
          <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-orange-500/10 text-orange-300">!</span>
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Diagnosis</h2>
            <p className="text-sm text-slate-500">Operational root cause and remediation — kept below security priorities</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="rounded-full bg-blue-500/15 px-3 py-1 text-xs font-semibold text-blue-300">{confidence}% confidence</span>
          <span className="text-slate-500">{open ? "▲" : "▼"}</span>
        </div>
      </button>

      {open && (
        <div className="space-y-5 border-t border-slate-700/30 p-6">
          {findings.length > 0 ? (
            <div>
              <div className="mb-3 flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Verified incidents</p>
                  <p className="mt-1 text-sm text-slate-400">Independent operational failures are shown separately.</p>
                </div>
                <span className="rounded-full bg-slate-800 px-3 py-1 text-xs font-semibold text-slate-300">{findings.length}</span>
              </div>
              <div className="space-y-3">
                {findings.map((finding, index) => (
                  <article key={`${finding.incident_type || "finding"}-${index}`} className="rounded-xl border border-slate-700/50 bg-slate-950/60 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="font-semibold text-slate-100">{finding.incident_type || `Incident ${index + 1}`}</p>
                        <p className="mt-1 text-sm text-slate-300">{finding.root_cause || finding.explanation || "No root cause supplied."}</p>
                      </div>
                      <span className="rounded-full bg-blue-500/10 px-2 py-1 text-[10px] font-semibold text-blue-300">{Math.round((finding.confidence || 0) * 100)}%</span>
                    </div>
                    {finding.explanation && <p className="mt-3 rounded-lg bg-slate-900 p-3 text-sm leading-6 text-slate-400">{finding.explanation}</p>}
                    {finding.affected_resources?.length ? <div className="mt-3 flex flex-wrap gap-2">{finding.affected_resources.map((resource) => <span key={resource} className="rounded-md bg-slate-800 px-2 py-1 font-mono text-[11px] text-cyan-300">{resource}</span>)}</div> : null}
                  </article>
                ))}
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-700/50 bg-slate-950/50 p-5 text-sm text-slate-400">{investigation.diagnosis?.root_cause || "No verified operational issue was found."}</div>
          )}

          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Suggested fix</p>
            <div className="mt-2 rounded-xl border border-slate-800 bg-slate-950/60 p-4"><FixDisplay fix={investigation.diagnosis?.fix || ""} /></div>
          </div>

          <RemediationPanel remediationId={investigation.remediation_id} investigation={investigation} onUpdate={onUpdate} />

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Kubectl command</p>
              <pre className="mt-2 min-h-20 overflow-x-auto rounded-xl border border-slate-700 bg-slate-950 p-4 font-mono text-xs text-emerald-300">{investigation.diagnosis?.kubectl_command || "No command suggested."}</pre>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Prevention</p>
              <p className="mt-2 min-h-20 rounded-xl border border-slate-700 bg-slate-950 p-4 text-sm leading-6 text-slate-300">{investigation.diagnosis?.prevention || "No prevention guidance returned."}</p>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

export default function DashboardSecurity() {
  const router = useRouter();
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [selectedContext, setSelectedContext] = useState("");
  const [current, setCurrent] = useState<Investigation | null>(null);
  const [history, setHistory] = useState<Investigation[]>([]);
  const [loadingClusters, setLoadingClusters] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [error, setError] = useState("");
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const startedRef = useRef<number>(0);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/login"); return; }
    fetchClusters();
    fetchHistory();
    return () => { if (pollRef.current) clearTimeout(pollRef.current); };
  }, [router]);

  const fetchClusters = async () => {
    try {
      const res = await apiClient.get("/clusters");
      const list = (res.data.clusters || []) as Cluster[];
      setClusters(list);
      setSelectedContext(list.find((c) => c.current)?.name || list[0]?.name || "");
    } catch (err: any) {
      if (err.response?.status === 401) router.push("/login");
      setError(err.response?.data?.detail || "Unable to load clusters");
    } finally { setLoadingClusters(false); }
  };

  const fetchHistory = async () => {
    try { const res = await apiClient.get("/investigations"); setHistory(res.data.investigations || []); }
    catch (err: any) { if (err.response?.status === 401) router.push("/login"); }
  };

  const fetchCurrent = async (id: string) => {
    try {
      const res = await apiClient.get(`/investigations/${id}`);
      const inv = res.data.investigation as Investigation;
      setCurrent(inv);
      return inv;
    } catch (err: any) {
      if (err.response?.status === 401) router.push("/login");
      return null;
    }
  };

  const startInvestigation = async () => {
    if (pollRef.current) clearTimeout(pollRef.current);
    setInvestigating(true); setCurrent(null); setError(""); startedRef.current = Date.now();
    try {
      const res = await apiClient.post("/investigate", { context: selectedContext });
      const id = res.data.investigation_id;
      const poll = async () => {
        if (Date.now() - startedRef.current > MAX_MS) {
          setInvestigating(false); setError("Diagnosis is taking longer than expected. The security scan should already be visible above."); return;
        }
        const inv = await fetchCurrent(id);
        if (inv?.status === "completed" || inv?.status === "failed") {
          setInvestigating(false); if (inv.status === "failed") setError((inv as any).error || "Investigation failed"); fetchHistory(); return;
        }
        pollRef.current = setTimeout(poll, POLL_MS);
      };
      await poll();
    } catch (err: any) {
      setInvestigating(false); setError(err.response?.data?.detail || "Investigation failed to start");
    }
  };

  const logout = () => { localStorage.removeItem("token"); router.push("/login"); };
  const reported = new Set((current?.steps || []).map((s) => s.name));

  return (
    <div className="min-h-screen bg-slate-50 p-4 text-slate-900 antialiased dark:bg-slate-950 dark:text-slate-100 md:p-8">
      <div className="mx-auto max-w-5xl space-y-5">
        <header className="flex items-center justify-between rounded-2xl border border-slate-700/30 bg-slate-900/70 px-6 py-4 shadow-lg backdrop-blur">
          <div><h1 className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-2xl font-bold text-transparent md:text-3xl">AI Kubernetes Agent</h1><p className="mt-1 text-xs text-slate-500">Security-first cluster triage · proof before action</p></div>
          <div className="flex items-center gap-2"><ThemeToggle /><button onClick={logout} className="rounded-lg px-3 py-2 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-100">Log out</button></div>
        </header>

        {loadingClusters ? <div className="rounded-2xl border border-slate-700/30 bg-slate-900/70 p-6 text-center text-slate-400">Loading clusters...</div> : clusters.length === 0 ? <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-6 text-rose-200">No Kubernetes clusters found. Check your kubeconfig.</div> : (
          <section className="rounded-2xl border border-slate-700/30 bg-slate-900/70 p-5 shadow-lg backdrop-blur">
            <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between"><div><label className="text-xs font-semibold uppercase tracking-wider text-slate-500">Cluster</label><select value={selectedContext} onChange={(e) => setSelectedContext(e.target.value)} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-slate-100 md:w-[560px]">{clusters.map((c) => <option key={c.name} value={c.name}>{c.name} — {c.server || c.cluster_name}</option>)}</select></div><button onClick={startInvestigation} disabled={investigating} className="rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-3 font-semibold text-white shadow-lg disabled:cursor-not-allowed disabled:opacity-50">{investigating ? "Scanning + diagnosing…" : "Investigate Cluster"}</button></div>
          </section>
        )}

        {error && <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">{error}</div>}

        {current && (
          <section className="rounded-2xl border border-slate-700/30 bg-slate-900/70 p-4 shadow-lg">
            <div className="mb-3 flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Investigation progress</p><p className="mt-1 text-xs text-slate-600">Security results are persisted as soon as the fast scan finishes; AI diagnosis continues independently.</p></div><span className={`rounded-full px-3 py-1 text-xs font-semibold ${investigating ? "bg-blue-500/10 text-blue-300" : "bg-emerald-500/10 text-emerald-300"}`}>{investigating ? "RUNNING" : current.status.toUpperCase()}</span></div>
            <div className="flex flex-wrap gap-2">{STEPS.map((step) => <span key={step} className={`rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold ${reported.has(step) ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-300" : "border-slate-800 bg-slate-950 text-slate-600"}`}>{reported.has(step) ? "✓ " : ""}{step}</span>)}</div>
          </section>
        )}

        {current?.security_summary && <SecuritySummary summary={current.security_summary} />}
        {current?.diagnosis && <DiagnosisSection investigation={current} onUpdate={setCurrent} />}

        <section className="rounded-2xl border border-slate-700/30 bg-slate-900/70 p-5 shadow-lg">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Recent investigations</h2>
          {history.length === 0 ? <p className="text-sm text-slate-500">No investigations yet.</p> : <div className="space-y-2">{history.slice(0, 5).map((inv) => <div key={inv.id} className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/50 px-4 py-3"><div className="min-w-0"><p className="truncate text-sm font-medium text-slate-200">{inv.root_cause || inv.status}</p><p className="mt-1 text-[10px] text-slate-600">{new Date(inv.created_at).toLocaleString()}</p></div><span className="rounded-full bg-blue-500/10 px-2 py-1 text-[10px] text-blue-300">{Math.round((inv.confidence || 0) * 100)}%</span></div>)}</div>}
        </section>
        <MetricsPanel />
      </div>
    </div>
  );
}
