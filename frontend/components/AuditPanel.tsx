"use client";

interface AuditCheck {
  name: string;
  status: "PASS" | "WARN" | "FAIL" | string;
}

interface AuditRecord {
  incident_id?: string;
  investigation_id?: string;
  remediation_id?: string;
  timestamp?: string;
  affected_cluster?: string;
  namespace?: string;
  kind?: string;
  resource?: string;
  diagnosis?: {
    root_cause?: string;
    explanation?: string;
    confidence?: number;
    evidence_references?: { source?: string; description?: string }[];
  };
  proposed_operation?: {
    tool?: string;
    arguments?: Record<string, unknown>;
    risk?: string;
    summary?: string;
  };
  previewed_changes?: { path?: string; before?: string; after?: string }[];
  policy_decision?: {
    allowed?: boolean;
    risk?: string;
    violations?: string[];
    warnings?: string[];
  };
  approval_status?: string;
  approval_timestamp?: string;
  execution_start?: string;
  execution_end?: string;
  execution_result?: unknown;
  verification_result?: { status: string; checks: AuditCheck[] };
  rollback_information?: unknown;
  rollback_result?: unknown;
  status?: string;
  error?: string;
}

interface AuditPanelProps {
  audit: AuditRecord | null | undefined;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">{title}</h4>
      <div className="text-sm text-slate-300">{children}</div>
    </div>
  );
}

function Badge({ children, color = "slate" }: { children: React.ReactNode; color?: "slate" | "emerald" | "amber" | "rose" | "cyan" }) {
  const colors = {
    slate: "bg-slate-500/20 text-slate-300",
    emerald: "bg-emerald-500/20 text-emerald-300",
    amber: "bg-amber-500/20 text-amber-300",
    rose: "bg-rose-500/20 text-rose-300",
    cyan: "bg-cyan-500/20 text-cyan-300",
  };
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${colors[color]}`}>
      {children}
    </span>
  );
}

function statusColor(status?: string) {
  if (status === "RESOLVED" || status === "ROLLED_BACK" || status === "APPROVED" || status === "PASS") return "emerald";
  if (status === "FAILED" || status === "ROLLBACK_FAILED" || status === "REJECTED" || status === "FAIL") return "rose";
  if (status === "NOT_RESOLVED" || status === "WARN" || status === "PENDING") return "amber";
  return "slate";
}

function CodeBlock({ data }: { data: unknown }) {
  return (
    <pre className="mt-1 max-h-48 overflow-auto rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-300">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

export default function AuditPanel({ audit }: AuditPanelProps) {
  if (!audit) {
    return <p className="text-sm text-slate-400">No audit record available.</p>;
  }

  return (
    <div className="mt-4 space-y-5 rounded-xl border border-slate-700/30 bg-slate-950/50 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">Remediation Audit</h3>
        {audit.status && <Badge color={statusColor(audit.status)}>{audit.status}</Badge>}
        {audit.approval_status && <Badge color={statusColor(audit.approval_status)}>{audit.approval_status}</Badge>}
      </div>

      <Section title="What happened?">
        <p>
          <span className="text-slate-500">Resource:</span>{" "}
          {audit.kind || "unknown"}/{audit.namespace || "default"}/{audit.resource || "unknown"}
        </p>
        <p>
          <span className="text-slate-500">Cluster context:</span>{" "}
          {audit.affected_cluster || "default"}
        </p>
        <p>
          <span className="text-slate-500">Timestamp:</span>{" "}
          {audit.timestamp ? new Date(audit.timestamp).toLocaleString() : "—"}
        </p>
      </Section>

      {audit.diagnosis && (
        <Section title="Why did the AI recommend this?">
          <p><span className="text-slate-500">Root cause:</span> {audit.diagnosis.root_cause || "—"}</p>
          <p><span className="text-slate-500">Explanation:</span> {audit.diagnosis.explanation || "—"}</p>
          <p><span className="text-slate-500">Confidence:</span> {audit.diagnosis.confidence ?? "—"}</p>
          {audit.diagnosis.evidence_references && audit.diagnosis.evidence_references.length > 0 && (
            <ul className="mt-1 list-inside list-disc space-y-1">
              {audit.diagnosis.evidence_references.map((e, i) => (
                <li key={i}>{e.source}: {e.description}</li>
              ))}
            </ul>
          )}
        </Section>
      )}

      {audit.proposed_operation && (
        <Section title="What was proposed?">
          <p><span className="text-slate-500">Tool:</span> {audit.proposed_operation.tool || "—"}</p>
          <p><span className="text-slate-500">Risk:</span> {audit.proposed_operation.risk || "—"}</p>
          {audit.proposed_operation.arguments && <CodeBlock data={audit.proposed_operation.arguments} />}
        </Section>
      )}

      {audit.previewed_changes && audit.previewed_changes.length > 0 && (
        <Section title="Previewed changes">
          <div className="space-y-2">
            {audit.previewed_changes.map((c, i) => (
              <div key={i} className="rounded-lg border border-slate-700 bg-slate-900 p-2 font-mono text-xs">
                <p className="text-slate-400">{c.path}</p>
                <p className="text-rose-400">- {String(c.before ?? "unset")}</p>
                <p className="text-emerald-400">+ {String(c.after ?? "unset")}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {audit.policy_decision && (
        <Section title="Policy decision">
          <p>
            <span className="text-slate-500">Allowed:</span>{" "}
            {audit.policy_decision.allowed ? "Yes" : "No"}
          </p>
          <p><span className="text-slate-500">Risk:</span> {audit.policy_decision.risk || "—"}</p>
          {audit.policy_decision.violations && audit.policy_decision.violations.length > 0 && (
            <ul className="mt-1 list-inside list-disc space-y-1 text-rose-300">
              {audit.policy_decision.violations.map((v, i) => <li key={i}>{v}</li>)}
            </ul>
          )}
          {audit.policy_decision.warnings && audit.policy_decision.warnings.length > 0 && (
            <ul className="mt-1 list-inside list-disc space-y-1 text-amber-300">
              {audit.policy_decision.warnings.map((w, i) => <li key={i}>{w}</li>)}
            </ul>
          )}
        </Section>
      )}

      <Section title="Approval & execution">
        <p><span className="text-slate-500">Approval status:</span> {audit.approval_status || "—"}</p>
        <p><span className="text-slate-500">Approved at:</span> {audit.approval_timestamp ? new Date(audit.approval_timestamp).toLocaleString() : "—"}</p>
        <p><span className="text-slate-500">Execution start:</span> {audit.execution_start ? new Date(audit.execution_start).toLocaleString() : "—"}</p>
        <p><span className="text-slate-500">Execution end:</span> {audit.execution_end ? new Date(audit.execution_end).toLocaleString() : "—"}</p>
      </Section>

      {audit.verification_result && (
        <Section title="Did it work?">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-slate-500">Verification:</span>
            <Badge color={statusColor(audit.verification_result.status)}>{audit.verification_result.status}</Badge>
          </div>
          {audit.verification_result.checks && (
            <ul className="space-y-1">
              {audit.verification_result.checks.map((check, i) => (
                <li key={i} className="flex items-center justify-between text-sm">
                  <span>{check.name}</span>
                  <Badge color={statusColor(check.status)}>{check.status}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Section>
      )}

      {!!audit.rollback_information && (
        <Section title="Rollback information">
          <CodeBlock data={audit.rollback_information} />
        </Section>
      )}

      {!!audit.rollback_result && (
        <Section title="Rollback result">
          <CodeBlock data={audit.rollback_result} />
        </Section>
      )}

      {!!audit.execution_result && (
        <Section title="Execution result">
          <CodeBlock data={audit.execution_result} />
        </Section>
      )}

      {audit.error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-900/20 p-3 text-sm text-rose-200">
          <span className="font-semibold">Error:</span> {audit.error}
        </div>
      )}
    </div>
  );
}
