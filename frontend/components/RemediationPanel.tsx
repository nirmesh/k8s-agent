"use client";

import { useState } from "react";

import apiClient from "@/services/api";
import AuditPanel from "@/components/AuditPanel";
import type { Investigation, RemediationPlan } from "@/types";

interface RemediationPanelProps {
  remediationId?: string;
  investigation: Investigation;
  onUpdate: (investigation: Investigation) => void;
}

function riskClass(risk: string | undefined) {
  switch (risk?.toUpperCase()) {
    case "LOW":
      return "bg-emerald-500/20 text-emerald-300";
    case "MEDIUM":
      return "bg-amber-500/20 text-amber-300";
    case "HIGH":
      return "bg-orange-500/20 text-orange-300";
    case "CRITICAL":
      return "bg-red-500/20 text-red-300";
    default:
      return "bg-slate-500/20 text-slate-400";
  }
}

function targetId(target: RemediationPlan["target"]) {
  if (!target) return "unknown";
  const ns = target.namespace || "default";
  return `${target.kind}/${ns}/${target.name}`;
}

function StepIcon({ completed }: { completed: boolean }) {
  if (completed) {
    return (
      <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
      </svg>
    );
  }
  return (
    <svg className="h-4 w-4 animate-spin text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function CheckBadge({ status }: { status: "PASS" | "WARN" | "FAIL" | string }) {
  const base = "rounded px-2 py-0.5 text-xs font-semibold";
  if (status === "PASS") return <span className={`${base} bg-emerald-500/20 text-emerald-300`}>PASS</span>;
  if (status === "WARN") return <span className={`${base} bg-amber-500/20 text-amber-300`}>WARN</span>;
  if (status === "FAIL") return <span className={`${base} bg-rose-500/20 text-rose-300`}>FAIL</span>;
  return <span className={`${base} bg-slate-500/20 text-slate-400`}>{status}</span>;
}

export default function RemediationPanel({ remediationId, investigation, onUpdate }: RemediationPanelProps) {
  const [loading, setLoading] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const [showAudit, setShowAudit] = useState(false);
  const [audit, setAudit] = useState<unknown>(null);

  const plan = investigation.remediation_plan;
  const status = investigation.remediation_status;
  const verification = investigation.remediation_verification;

  async function refresh() {
    const r = await apiClient.get(`/investigations/${investigation.id}`);
    onUpdate(r.data.investigation as Investigation);
  }

  async function loadAudit() {
    if (!remediationId) return;
    try {
      const r = await apiClient.get(`/remediations/${remediationId}`);
      setAudit(r.data.audit);
      setShowAudit(true);
    } catch (err: any) {
    }
  }

  async function handleApprove() {
    if (!remediationId) return;
    setLoading(true);
    try {
      await apiClient.post(`/remediations/${remediationId}/execute`, {});
      await refresh();
    } catch (err: any) {
    } finally {
      setLoading(false);
    }
  }

  async function handleReject() {
    if (!remediationId) return;
    setLoading(true);
    try {
      await apiClient.post(`/remediations/${remediationId}/reject`, {});
      await refresh();
    } catch (err: any) {
    } finally {
      setLoading(false);
    }
  }

  async function handleRollback() {
    if (!remediationId) return;
    setLoading(true);
    try {
      await apiClient.post(`/remediations/${remediationId}/rollback`, {});
      await refresh();
    } catch (err: any) {
    } finally {
      setLoading(false);
    }
  }

  if (!plan && !status) return null;

  const failedBecauseNotResolved = status === "FAILED" && verification;

  return (
    <div className="rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-300">
        Proposed Remediation
      </h3>

      {status === "NEED_USER_INPUT" && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-900/20 p-3 text-amber-200">
          {plan?.summary || "No safe automated remediation could be determined from the current evidence."}
        </div>
      )}

      {(status === "AWAITING_APPROVAL" || status === "READY") && plan?.status === "READY" && (
        <div className="space-y-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Target</p>
              <p className="font-mono text-sm text-slate-200">{targetId(plan.target)}</p>
            </div>
            <span className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold ${riskClass(plan.risk)}`}>
              {plan.risk ?? "UNKNOWN"} risk
            </span>
          </div>

          {plan.changes && plan.changes.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Change</p>
              <div className="mt-1 overflow-x-auto rounded-lg border border-slate-700 bg-slate-900 p-3 font-mono text-sm">
                {plan.changes.map((c, i) => (
                  <div key={i} className="space-y-1">
                    <p className="text-slate-400">{c.path}</p>
                    <p className="text-rose-400">- {String(c.before ?? "unset")}</p>
                    <p className="text-emerald-400">+ {String(c.after ?? "unset")}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {plan.reason && (
            <p className="text-sm leading-relaxed text-slate-300">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Reason: </span>
              {plan.reason}
            </p>
          )}

          {plan.verification && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Verification</p>
              <p className="text-sm text-slate-300">{plan.verification.type}: {plan.verification.expected}</p>
            </div>
          )}

          {plan.rollback && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Rollback</p>
              <p className="text-sm text-slate-300">{plan.rollback.strategy}</p>
            </div>
          )}

          <div className="flex flex-col gap-2 pt-2 sm:flex-row">
            <button
              onClick={handleReject}
              disabled={loading}
              className="rounded-lg border border-rose-500/30 bg-rose-900/20 px-4 py-2 text-sm font-semibold text-rose-200 transition-colors hover:bg-rose-900/30 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Reject
            </button>
            <button
              onClick={handleApprove}
              disabled={loading || !remediationId}
              className="rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-lg transition-all hover:from-cyan-400 hover:to-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Working..." : "Approve & Fix"}
            </button>
          </div>
        </div>
      )}

      {(status === "EXECUTING" || status === "VERIFYING" || status === "ROLLING_BACK") && (
        <ul className="space-y-2">
          {(investigation.remediation_timeline || []).map((item, idx, arr) => {
            const isActive = idx === arr.length - 1 && (status === "EXECUTING" || status === "VERIFYING" || status === "ROLLING_BACK");
            return (
              <li key={idx} className="flex items-center gap-3 text-sm text-slate-300">
                <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-slate-700 bg-slate-900">
                  <StepIcon completed={isActive ? false : item.completed} />
                </span>
                {item.step}
              </li>
            );
          })}
          {(investigation.remediation_timeline || []).length === 0 && (
            <li className="flex items-center gap-3 text-sm text-slate-300">
              <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-slate-700 bg-slate-900">
                <StepIcon completed={false} />
              </span>
              {status === "ROLLING_BACK" ? "Rolling back..." : "Executing remediation..."}
            </li>
          )}
        </ul>
      )}

      {(status === "RESOLVED" || status === "ROLLED_BACK") && (
        <div className={`
          rounded-lg border p-3
          ${status === "RESOLVED" ? "border-emerald-500/30 bg-emerald-900/20 text-emerald-200" : "border-cyan-500/30 bg-cyan-900/20 text-cyan-200"}
        `}>
          {status === "RESOLVED"
            ? "Remediation completed and verified."
            : "Remediation was rolled back successfully."}
        </div>
      )}

      {failedBecauseNotResolved && (
        <div className="space-y-3">
          <div className="rounded-lg border border-amber-500/30 bg-amber-900/20 p-3 text-amber-200">
            Remediation did not resolve the incident.
          </div>
          {verification && (
            <div className="rounded-lg border border-slate-700 bg-slate-900 p-3">
              <div className="mb-2 flex items-center justify-between">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Verification checks</p>
                <button
                  onClick={() => setShowDetails(!showDetails)}
                  className="text-xs text-cyan-400 hover:text-cyan-300"
                >
                  {showDetails ? "Hide Details" : "View Details"}
                </button>
              </div>
              {showDetails && (
                <ul className="space-y-2">
                  {verification.checks.map((check, i) => (
                    <li key={i} className="flex items-center justify-between text-sm text-slate-300">
                      <span>{check.name}</span>
                      <CheckBadge status={check.status} />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
          <div className="flex flex-col gap-2 pt-2 sm:flex-row">
            <button
              onClick={handleRollback}
              disabled={loading || !remediationId}
              className="rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-lg transition-all hover:from-cyan-400 hover:to-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Working..." : "Roll Back"}
            </button>
          </div>
        </div>
      )}

      {status === "FAILED" && !verification && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-900/20 p-3 text-rose-200">
          Remediation failed{investigation.remediation_error ? `: ${investigation.remediation_error}` : "."}
        </div>
      )}

      {status === "ROLLBACK_FAILED" && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-900/20 p-3 text-rose-200">
          Rollback failed{investigation.remediation_error ? `: ${investigation.remediation_error}` : "."}
        </div>
      )}

      {status === "REJECTED" && (
        <div className="rounded-lg border border-slate-600/30 bg-slate-800/30 p-3 text-slate-300">
          Remediation was rejected.
        </div>
      )}

      {status === "NO_SAFE_REMEDIATION" && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-900/20 p-3 text-rose-200">
          No safe automated remediation is available for this diagnosis.
        </div>
      )}

      {remediationId && (
        <div className="pt-3">
          <button
            onClick={loadAudit}
            disabled={loading}
            className="text-sm text-cyan-400 hover:text-cyan-300 disabled:opacity-50"
          >
            {showAudit ? "Refresh Audit" : "View Full Audit"}
          </button>
          {showAudit && <AuditPanel audit={audit as any} />}
        </div>
      )}
    </div>
  );
}
