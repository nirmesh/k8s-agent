export interface HealthResponse { status: string; service: string; }
export interface InvestigationRequest { namespace?: string; }
export interface DiagnosisFinding { incident_type: string; root_cause: string; explanation: string; confidence: number; affected_resources: string[]; evidence_ids: string[]; }
export interface Diagnosis {
  status?: "DIAGNOSED" | "NEED_MORE_EVIDENCE" | "NO_ISSUE" | string;
  root_cause: string;
  explanation: string;
  fix: string;
  kubectl_command: string;
  prevention: string;
  confidence: number;
  affected_resources?: string[];
  findings?: DiagnosisFinding[];
  evidence?: any[];
}
export interface RemediationPlan {
  status: "READY" | "NEED_USER_INPUT" | "NO_SAFE_REMEDIATION";
  summary?: string; question?: string; root_cause?: string; confidence?: number;
  remediation_type?: "PATCH" | "CONFIG" | "CONTAINMENT" | "NEED_USER_INPUT" | "INVESTIGATE" | string;
  risk?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; tool?: string; arguments?: Record<string, unknown>;
  target?: { kind: string; namespace?: string; name: string };
  changes?: { path: string; before: string; after: string }[]; reason?: string;
  verification?: { type: string; expected: string }; rollback?: { available: boolean; strategy: string };
  kubectl_commands?: string[]; verification_steps?: string[]; rollback_steps?: string[];
}
export interface SecurityWorkload {
  name: string; namespace: string; kind: string; risk_score: number; counts: Record<string, number>;
  findings: { title: string; severity: string; category: string; cve_id?: string; recommendation?: string }[];
  internet_facing?: boolean; privileged?: boolean; host_network?: boolean; replicas?: number; running?: number; recommendation: string;
}
export interface NativePostureFinding {
  title?: string | null;
  severity: string;
  category?: string | null;
  resource: string;
  namespace?: string | null;
  source?: string | null;
  layer?: string | null;
  domain?: string | null;
  description?: string | null;
  recommendation?: string | null;
  impact?: string | null;
  rule_id?: string | null;
}
export interface SecuritySummary {
  status: "AVAILABLE" | "UNAVAILABLE"; reason?: string | null; cluster_security_score: number | null; score_basis?: string;
  scored_vulnerabilities?: number; unscored_unknown_vulnerabilities?: number; total_vulnerabilities: number;
  critical_vulnerabilities: number; high_vulnerabilities: number; medium_vulnerabilities: number; low_vulnerabilities: number; unknown_vulnerabilities: number;
  total_misconfigurations: number; total_exposed_secrets: number; workload_count?: number; affected_workloads?: number; affected_namespaces?: number;
  critical_workloads?: SecurityWorkload[]; high_risk_namespaces?: { namespace: string; average_score: number }[]; top_10_risks: SecurityWorkload[]; top_recommendations: string[];
  native_posture_findings?: NativePostureFinding[];
}
export interface Investigation {
  id: string; status: string; steps: { name: string; completed: boolean; timestamp: string }[]; diagnosis: Diagnosis | null; remediation_plan: RemediationPlan | null;
  remediation_id?: string; remediation_status?: string; remediation_timeline?: { step: string; completed: boolean; timestamp: string }[]; remediation_error?: string | null;
  remediation_verification?: { status: string; checks: { name: string; status: "PASS" | "WARN" | "FAIL" }[] } | null;
  root_cause: string; namespace: string; confidence: number; operational_evidence?: any | null; security_summary?: SecuritySummary | null; security_evidence?: any[] | null;
  created_at: string; updated_at: string;
}
export interface Cluster { name: string; current: boolean; server: string; namespace: string; cluster_name: string; }
