"use client";

import { useEffect, useState } from "react";

import apiClient from "@/services/api";

type MetricValue = { resultType?: string; result?: unknown } | null;

interface MetricsData {
  cpu: MetricValue;
  memory: MetricValue;
  latency: MetricValue;
  error_rate: MetricValue;
  restart_count: MetricValue;
  alert_state: MetricValue;
  timeline: unknown[];
}

interface MetricsPanelProps {
  namespace?: string;
  pod?: string;
}

const CARD_TITLES: Record<string, string> = {
  cpu: "CPU",
  memory: "Memory",
  latency: "Latency",
  error_rate: "Error Rate",
  restart_count: "Restart Count",
  alert_state: "Alert State",
};

function MetricCard({ title, data }: { title: string; data: MetricValue }) {
  const isEmpty = !data || !data.result || (Array.isArray(data.result) && data.result.length === 0);
  return (
    <div className="rounded-xl border border-slate-700/30 bg-slate-900/60 p-4 shadow-lg backdrop-blur">
      <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">{title}</p>
      <div className="mt-2 overflow-x-auto rounded-lg bg-slate-950 p-2 font-mono text-xs text-slate-300">
        {isEmpty ? (
          <span className="text-slate-500">No data</span>
        ) : (
          <pre className="whitespace-pre-wrap break-words">
            {JSON.stringify(data, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

export default function MetricsPanel({ namespace = "", pod = "" }: MetricsPanelProps) {
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const fetchMetrics = async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      if (namespace) params.set("namespace", namespace);
      if (pod) params.set("pod", pod);
      const res = await apiClient.get(`/metrics?${params.toString()}`);
      setMetrics(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to load metrics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, [namespace, pod]);

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-100">Metrics</h2>
        <button
          onClick={fetchMetrics}
          disabled={loading}
          className="rounded-lg bg-cyan-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-900/20 p-3 text-rose-200">
          {error}
        </div>
      )}

      {metrics && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(CARD_TITLES).map(([key, title]) => (
            <MetricCard key={key} title={title} data={metrics[key as keyof MetricsData] as MetricValue} />
          ))}
        </div>
      )}
    </section>
  );
}
