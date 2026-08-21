"use client";

import { useMemo, useState } from "react";
import type { SecuritySummary, SecurityWorkload } from "@/types";

interface Props { summary: SecuritySummary | null | undefined; }

type Issue = {
  id: string;
  rank: number;
  title: string;
  severity: string;
  score: number;
  resource: string;
  category: string;
  evidence: string;
  why: string;
  fix: string;
  verify: string;
  cve?: string;
};

const SEVERITY_BASE: Record<string, number> = { CRITICAL: 96, HIGH: 86, MEDIUM: 68, LOW: 42, UNKNOWN: 25 };

function scoreIssue(finding: SecurityWorkload["findings"][number], workload: SecurityWorkload) {
  let score = SEVERITY_BASE[finding.severity?.toUpperCase()] ?? 25;
  if (workload.internet_facing) score += 4;
  if (workload.privileged) score += 4;
  if (workload.host_network) score += 3;
  return Math.min(99, score);
}

function severityClass(severity: string) {
  switch (severity.toUpperCase()) {
    case "CRITICAL": return "border-rose-500/30 bg-rose-500/10 text-rose-300";
    case "HIGH": return "border-orange-500/30 bg-orange-500/10 text-orange-300";
    case "MEDIUM": return "border-amber-500/30 bg-amber-500/10 text-amber-300";
    default: return "border-slate-600 bg-slate-800/60 text-slate-300";
  }
}

function buildIssues(summary: SecuritySummary): Issue[] {
  const candidates: Issue[] = [];
  (summary.top_10_risks || []).forEach((workload, workloadIndex) => {
    (workload.findings || []).forEach((finding, findingIndex) => {
      const severity = (finding.severity || "UNKNOWN").toUpperCase();
      const resource = `${workload.kind || "Workload"}/${workload.namespace}/${workload.name}`;
      const context: string[] = [];
      if (workload.internet_facing) context.push("internet-facing");
      if (workload.privileged) context.push("privileged container");
      if (workload.host_network) context.push("host networking");
      const contextText = context.length ? ` It also has ${context.join(", ")}.` : "";
      const cve = finding.cve_id;
      candidates.push({
        id: `${workloadIndex}-${findingIndex}-${finding.title}`,
        rank: 0,
        title: finding.title || "Security issue requires attention",
        severity,
        score: scoreIssue(finding, workload),
        resource,
        category: finding.category || "security finding",
        cve,
        evidence: `${resource}${cve ? ` · ${cve}` : ""} · severity ${severity}`,
        why: severity === "CRITICAL"
          ? `A critical finding is verified on this workload.${contextText} Compromise of the affected component could have a materially high blast radius.`
          : severity === "HIGH"
            ? `A high-severity finding is verified on this workload.${contextText} It should be addressed before lower-risk cleanup.`
            : `A ${severity.toLowerCase()} finding is verified on this workload.${contextText}`,
        fix: finding.recommendation || workload.recommendation || "Apply the least-privilege configuration required by this workload and redeploy it.",
        verify: "Re-scan this workload after the change and confirm the finding is no longer reported.",
      });
    });
  });

  const unique = new Map<string, Issue>();
  candidates.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  candidates.forEach((issue) => {
    const key = `${issue.resource}|${issue.title}`;
    if (!unique.has(key)) unique.set(key, issue);
  });

  return Array.from(unique.values()).slice(0, 10).map((issue, index) => ({ ...issue, rank: index + 1 }));
}

export default function SecuritySummary({ summary }: Props) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const issues = useMemo(() => summary ? buildIssues(summary) : [], [summary]);
  const critical = issues.filter((i) => i.severity === "CRITICAL").length;
  const high = issues.filter((i) => i.severity === "HIGH").length;

  if (!summary) return null;
  if (summary.status === "UNAVAILABLE") {
    return (
      <section className="rounded-2xl border border-rose-700/30 bg-slate-900/70 p-6 shadow-lg">
        <h2 className="text-lg font-semibold text-rose-300">Security Data Unavailable</h2>
        <p className="mt-2 text-sm text-slate-300">{summary.reason || "Security evidence could not be collected from the cluster."}</p>
      </section>
    );
  }

  const toggle = (id: string) => setExpanded((current) => ({ ...current, [id]: !current[id] }));

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-700/40 bg-slate-900/70 shadow-xl backdrop-blur">
      <div className="border-b border-slate-700/30 px-6 py-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-rose-500/10 text-rose-300">◆</span>
              <div>
                <h2 className="text-xl font-semibold text-slate-100">Security Findings</h2>
                <p className="mt-0.5 text-sm text-slate-400">The 10 issues that deserve attention first</p>
              </div>
            </div>
            <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
              <span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-slate-600 text-[10px] font-bold text-slate-400" title="Only findings already present in collected security evidence are shown. Scores prioritize severity and verified workload context; they are not exploit probability.">i</span>
              <span>Evidence first · no unverified attack claims</span>
            </div>
          </div>
          <div className="hidden text-right sm:block">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Immediate attention</p>
            <p className="text-3xl font-bold text-slate-100">{issues.length}</p>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4">
            <p className="text-[11px] uppercase tracking-wider text-rose-300">Critical</p>
            <p className="mt-1 text-2xl font-bold text-slate-100">{critical}</p>
          </div>
          <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
            <p className="text-[11px] uppercase tracking-wider text-orange-300">High</p>
            <p className="mt-1 text-2xl font-bold text-slate-100">{high}</p>
          </div>
          <div className="rounded-xl border border-slate-700/40 bg-slate-950/50 p-4">
            <p className="text-[11px] uppercase tracking-wider text-slate-500">Verified workloads</p>
            <p className="mt-1 text-2xl font-bold text-slate-100">{summary.affected_workloads ?? summary.workload_count ?? 0}</p>
          </div>
          <div className="rounded-xl border border-slate-700/40 bg-slate-950/50 p-4">
            <p className="text-[11px] uppercase tracking-wider text-slate-500">All findings</p>
            <p className="mt-1 text-2xl font-bold text-slate-100">{(summary.total_vulnerabilities ?? 0) + (summary.total_misconfigurations ?? 0) + (summary.total_exposed_secrets ?? 0)}</p>
          </div>
        </div>
      </div>

      <div className="px-4 py-4 sm:px-6 sm:py-6">
        {issues.length === 0 ? (
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6">
            <p className="font-semibold text-emerald-300">No immediate issues were verified.</p>
            <p className="mt-1 text-sm text-slate-400">The current security summary did not expose enough workload-level evidence to construct a top-10 list. Nothing is invented to fill the list.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {issues.map((issue) => {
              const isOpen = expanded[issue.id] ?? issue.rank <= 3;
              return (
                <article key={issue.id} className="overflow-hidden rounded-xl border border-slate-700/40 bg-slate-950/55">
                  <button onClick={() => toggle(issue.id)} className="flex w-full items-center gap-4 px-4 py-4 text-left transition-colors hover:bg-slate-900 sm:px-5">
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-slate-800 text-sm font-bold text-slate-300">{issue.rank}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-md border px-2 py-1 text-[10px] font-bold tracking-wide ${severityClass(issue.severity)}`}>{issue.severity}</span>
                        <span className="rounded-md bg-slate-800 px-2 py-1 text-[10px] font-semibold text-slate-400">{issue.category}</span>
                        {issue.cve && <span className="font-mono text-[10px] text-slate-500">{issue.cve}</span>}
                      </div>
                      <h3 className="mt-2 truncate font-semibold text-slate-100">{issue.title}</h3>
                      <p className="mt-1 truncate font-mono text-xs text-cyan-300/80">{issue.resource}</p>
                    </div>
                    <div className="hidden shrink-0 text-right sm:block">
                      <p className="text-[10px] uppercase tracking-wider text-slate-600">Risk</p>
                      <p className={`text-xl font-bold ${issue.score >= 90 ? "text-rose-300" : issue.score >= 75 ? "text-orange-300" : "text-amber-300"}`}>{issue.score}</p>
                    </div>
                    <span className="shrink-0 text-slate-500">{isOpen ? "▲" : "▼"}</span>
                  </button>

                  {isOpen && (
                    <div className="grid gap-4 border-t border-slate-800/70 px-4 py-4 sm:grid-cols-3 sm:px-5">
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Why it matters</p>
                        <p className="mt-1.5 text-sm leading-6 text-slate-300">{issue.why}</p>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Proof</p>
                        <p className="mt-1.5 break-words font-mono text-xs leading-5 text-cyan-200">{issue.evidence}</p>
                      </div>
                      <div className="rounded-lg border border-emerald-500/10 bg-emerald-500/5 p-3">
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300">Fix in 2 steps</p>
                        <p className="mt-1.5 text-sm leading-5 text-slate-300"><span className="font-semibold text-slate-200">1.</span> {issue.fix}</p>
                        <p className="mt-2 text-sm leading-5 text-slate-400"><span className="font-semibold text-slate-300">2.</span> {issue.verify}</p>
                      </div>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </div>

      <div className="border-t border-slate-700/30 px-6 py-3 text-xs text-slate-600">
        Showing the highest-priority verified findings available from the current security evidence. Scores combine finding severity with observed workload context; they do not claim successful exploitation.
      </div>
    </section>
  );
}
