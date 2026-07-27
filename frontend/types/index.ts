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

export interface Investigation {
  id: string;
  status: string;
  steps: { name: string; completed: boolean; timestamp: string }[];
  diagnosis: Diagnosis | null;
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
