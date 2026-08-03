"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import apiClient from "@/services/api";
import RemediationPanel from "@/components/RemediationPanel";
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

export default function Dashboard() {
  const router = useRouter();
  const [history, setHistory] = useState<Investigation[]>([]);
  const [current, setCurrent] = useState<Investigation | null>(null);
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [selectedContext, setSelectedContext] = useState("");
  const [loadingClusters, setLoadingClusters] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    fetchHistory();
    fetchClusters();
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
    } catch (err: any) {
      setError("Failed to refresh investigation status");
    }
  };

  useEffect(() => {
    if (!current?.id || !current.remediation_status) return;
    if (
      current.remediation_status !== "EXECUTING" &&
      current.remediation_status !== "VERIFYING"
    ) {
      return;
    }
    const id = current.id;
    const interval = setInterval(() => {
      fetchCurrent(id);
    }, 2000);
    return () => clearInterval(interval);
  }, [current?.id, current?.remediation_status]);

  const startInvestigation = async () => {
    setInvestigating(true);
    setCurrent(null);
    setError("");

    try {
      const res = await apiClient.post("/investigate", { context: selectedContext });
      const id = res.data.investigation_id;

      const interval = setInterval(async () => {
        try {
          const r = await apiClient.get(`/investigations/${id}`);
          const inv: Investigation = r.data.investigation;
          setCurrent(inv);

          if (inv.status === "completed" || inv.status === "failed") {
            clearInterval(interval);
            setInvestigating(false);
            fetchHistory();
          }
        } catch (e: any) {
          clearInterval(interval);
          setInvestigating(false);
          setError("Failed to fetch investigation status");
        }
      }, 2000);
    } catch (err: any) {
      setInvestigating(false);
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
            <h1 className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-2xl font-bold text-transparent md:text-3xl">
              AI Kubernetes Agent
            </h1>
            <span className="text-xs italic text-slate-400">No grepping at 2 am</span>
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <button
              onClick={logout}
              className="rounded-lg px-3 py-2 text-sm font-medium text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100"
            >
              Log out
            </button>
          </div>
        </header>

        {loadingClusters ? (
          <div className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 text-center text-slate-400 shadow-lg backdrop-blur">
            Loading clusters...
          </div>
        ) : clusters.length === 0 ? (
          <div className="rounded-2xl border border-red-500/30 bg-red-900/20 p-6 text-red-200 shadow-lg backdrop-blur">
            No Kubernetes clusters found. Check your kubeconfig.
          </div>
        ) : (
          <section className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
              Select Cluster
            </label>
            <select
              value={selectedContext}
              onChange={(e) => setSelectedContext(e.target.value)}
              className="mt-3 w-full rounded-xl border border-slate-600 bg-slate-950 px-4 py-3 text-slate-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              {clusters.map((c) => (
                <option key={c.name} value={c.name} className="bg-slate-950 text-slate-100">
                  {c.name} — {c.server || c.cluster_name}
                </option>
              ))}
            </select>
          </section>
        )}

        <button
          onClick={startInvestigation}
          disabled={investigating || loadingClusters || clusters.length === 0}
          className="w-full rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-3.5 text-center font-semibold text-white shadow-lg shadow-cyan-900/20 transition-all hover:from-cyan-400 hover:to-blue-500 hover:shadow-xl disabled:cursor-not-allowed disabled:opacity-50"
        >
          {investigating ? "Investigating..." : "Investigate Cluster"}
        </button>

        {error && (
          <div className="rounded-2xl border border-red-500/30 bg-red-900/20 p-4 text-sm text-red-200">
            {error}
          </div>
        )}

        {current && (
          <section className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur">
            <h2 className="mb-4 text-lg font-semibold text-slate-100">Investigation Status</h2>
            <ul className="space-y-3">
              {(() => {
                const reported = new Set(current.steps.map((s) => s.name));
                const highestCompleted = ALL_STEPS.reduce((max, step, idx) =>
                  reported.has(step) ? idx : max, -1
                );
                const completedIndex = investigating ? highestCompleted : ALL_STEPS.length - 1;
                const completed = new Set(ALL_STEPS.slice(0, completedIndex + 1));
                const activeIndex = investigating
                  ? Math.min(completedIndex + 1, ALL_STEPS.length - 1)
                  : -1;
                return ALL_STEPS.map((step, index) => {
                  const isCompleted = completed.has(step);
                  const isActive = index === activeIndex && !isCompleted;
                  return (
                    <li
                      key={step}
                      className={isCompleted
                        ? "flex items-center gap-4 rounded-xl bg-emerald-500/10 px-4 py-3 text-emerald-100"
                        : isActive
                          ? "flex items-center gap-4 rounded-xl bg-blue-500/10 px-4 py-3 text-blue-200"
                          : "flex items-center gap-4 rounded-xl px-4 py-3 text-slate-500"}
                    >
                      <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-slate-700 bg-slate-950 text-xs font-semibold">
                        {isCompleted ? (
                          <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                          </svg>
                        ) : isActive ? (
                          <svg className="h-4 w-4 animate-spin text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                          </svg>
                        ) : (
                          index + 1
                        )}
                      </span>
                      <span className="font-medium">{step}</span>
                    </li>
                  );
                });
              })()}
            </ul>
          </section>
        )}

        {current?.diagnosis && (
          <section className="overflow-hidden rounded-2xl border border-slate-700/30 bg-slate-900/60 shadow-lg backdrop-blur">
            <div className="flex items-center justify-between border-b border-slate-700/30 bg-gradient-to-r from-rose-500/10 to-orange-500/10 px-6 py-4">
              <div className="flex items-center gap-3">
                <svg className="h-6 w-6 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="flex flex-col">
                  <h2 className="text-lg font-semibold text-slate-100">Diagnosis</h2>
                </div>
              </div>
              <span className="rounded-full bg-blue-500/20 px-3 py-1 text-sm font-semibold text-blue-300">
                {Math.round((current.diagnosis.confidence || 0) * 100)}% confidence
              </span>
            </div>
            <div className="space-y-6 p-6">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Root Cause</p>
                <p className="mt-1 text-lg font-medium text-slate-100">{current.diagnosis.root_cause}</p>
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Explanation</p>
                <p className="mt-1 leading-relaxed text-slate-300">{current.diagnosis.explanation}</p>
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Suggested Fix</p>
                <div className="mt-2 text-slate-300">
                  <FixDisplay fix={current.diagnosis.fix} />
                </div>
              </div>

              <RemediationPanel
                remediationId={current.remediation_id}
                investigation={current}
                onUpdate={setCurrent}
              />

              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Kubectl Command</p>
                <div className="mt-2 overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 font-mono text-sm text-emerald-400">
                  {current.diagnosis.kubectl_command || "No command suggested."}
                </div>
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Prevention</p>
                <p className="mt-1 leading-relaxed text-slate-300">{current.diagnosis.prevention}</p>
              </div>
            </div>
          </section>
        )}

        <section className="rounded-2xl border border-slate-700/30 bg-slate-900/60 p-6 shadow-lg backdrop-blur">
          <h2 className="mb-4 text-lg font-semibold text-slate-100">Recent Investigations</h2>
          {history.length === 0 ? (
            <p className="text-slate-500">No investigations yet.</p>
          ) : (
            <ul className="space-y-3">
              {history.map((inv) => (
                <li
                  key={inv.id}
                  className="flex items-start justify-between rounded-xl border border-slate-700/30 bg-slate-950/50 p-4"
                >
                  <div>
                    <p className="font-medium text-slate-100">{inv.root_cause || inv.status}</p>
                    <p className="mt-1 text-xs text-slate-500">{new Date(inv.created_at).toLocaleString()}</p>
                  </div>
                  <span className="shrink-0 rounded-full bg-blue-500/20 px-2.5 py-1 text-xs font-semibold text-blue-300">
                    {Math.round((inv.confidence || 0) * 100)}%
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
