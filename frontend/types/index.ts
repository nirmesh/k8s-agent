export interface HealthResponse {
  status: string;
  service: string;
}

export interface InvestigationRequest {
  namespace?: string;
}

export interface Diagnosis {
  root_cause: string;
  explanation: string;
  fix: string;
  kubectl_command: string;
  prevention: string;
  confidence: number;
}

export interface RemediationPlan {
  status: "READY" | "NEED_USER_INPUT" | "NO_SAFE_REMEDIATION";
  summary?: string;
  question?: string;
  root_cause?: string;
  confidence?: number;
  remediation_type?: "PATCH" | "CONFIG" | "CONTAINMENT" | "NEED_USER_INPUT" | "INVESTIGATE" | string;
  risk?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  tool?: string;
  arguments?: Record<string, unknown>;
  target?: { kind: string; namespace?: string; name: string };
  changes?: { path: string; before: string; after: string }[];
  reason?: string;
  verification?: { type: string; expected: string };
  rollback?: { available: boolean; strategy: string };
  kubectl_commands?: string[];
  verification_steps?: string[];
  rollback_steps?: string[];
}

export interface Investigation {
  id: string;
  status: string;
  steps: { name: string; completed: boolean; timestamp: string }[];
  diagnosis: Diagnosis | null;
  remediation_plan: RemediationPlan | null;
  remediation_id?: string;
  remediation_status?: string;
  remediation_timeline?: { step: string; completed: boolean; timestamp: string }[];
  remediation_error?: string | null;
  remediation_verification?: {
    status: string;
    checks: { name: string; status: "PASS" | "WARN" | "FAIL" }[];
  } | null;
  root_cause: string;
  namespace: string;
  confidence: number;
  created_at: string;
  updated_at: string;
}

export interface Cluster {
  name: string;
  current: boolean;
  server: string;
  namespace: string;
  cluster_name: string;
}
