# AI-K9s Production Helm Deployment

## Recommended shipping model

For production, ship AI-K9s as container images plus a Helm chart. Keep the local Docker Compose workflow for development and keep the standalone LangGraph development server for Studio/debugging only.

## Production request path

```text
Customer browser
    |
    v
AI-K9s frontend Service
    |
    v
AI-K9s backend Pod
    |
    +--> LangGraph graph (in-process)
    |
    +--> Ollama / configured LLM endpoint
    |
    +--> MongoDB
    |
    +--> Kubernetes API Server
             ^
             |
       ServiceAccount
             |
          ClusterRole
```

The backend does not require a customer's administrator kubeconfig and does not require `kubectl` in the application image.

## Install

Publish the two application images to a registry reachable by the cluster. Then install:

```bash
helm upgrade --install ai-k9s ./deploy/helm/ai-k9s \
  --namespace ai-k9s \
  --create-namespace \
  --set backend.image.repository=REGISTRY/ai-k9s-backend \
  --set backend.image.tag=TAG \
  --set frontend.image.repository=REGISTRY/ai-k9s-frontend \
  --set frontend.image.tag=TAG \
  --set backend.env.ollamaHost=http://OLLAMA_HOST:11434
```

## Feature switches

The chart uses explicit enable/disable values so a customer can render only the components they approve:

```yaml
features:
  backend:
    enabled: true
  frontend:
    enabled: true
  mongodb:
    enabled: true
  langgraphStudio:
    enabled: false

rbac:
  create: true
  remediation:
    enabled: false
  secrets:
    enabled: false
```

Useful examples:

```bash
# Disable bundled MongoDB and use an external database.
helm upgrade --install ai-k9s ./deploy/helm/ai-k9s \
  --namespace ai-k9s --create-namespace \
  --set features.mongodb.enabled=false \
  --set backend.env.mongodbUrl='mongodb://USER:PASSWORD@mongo.example:27017/ai_kubernetes_agent'

# Explicitly opt into remediation RBAC. Do not enable by default.
helm upgrade --install ai-k9s ./deploy/helm/ai-k9s \
  --namespace ai-k9s \
  --set rbac.remediation.enabled=true
```

## RBAC

The default chart is read-only. It grants `get`, `list`, and `watch` to the core workload/network/storage resources used by the investigation engine, plus CRD discovery. Secret access is disabled.

The default posture intentionally does not grant `patch`, `update`, or `delete` permissions.

Before applying the chart in a customer cluster, inspect the rendered RBAC:

```bash
helm template ai-k9s ./deploy/helm/ai-k9s \
  --set backend.image.repository=REGISTRY/ai-k9s-backend \
  --set frontend.image.repository=REGISTRY/ai-k9s-frontend \
  --set backend.env.ollamaHost=http://OLLAMA_HOST:11434 \
  | less
```

After installation:

```bash
kubectl auth can-i --list \
  --as=system:serviceaccount:ai-k9s:$(kubectl get sa -n ai-k9s -o jsonpath='{.items[0].metadata.name}')
```

Test the important boundaries explicitly:

```bash
kubectl auth can-i get pods --all-namespaces --as=system:serviceaccount:ai-k9s:<service-account>
kubectl auth can-i patch deployments --all-namespaces --as=system:serviceaccount:ai-k9s:<service-account>
kubectl auth can-i get secrets --all-namespaces --as=system:serviceaccount:ai-k9s:<service-account>
```

Expected default result:

- pod read: yes
- deployment patch: no
- secret read: no

## Authentication to Kubernetes API

The Helm deployment creates a dedicated ServiceAccount. The backend Pod receives the ServiceAccount token and CA from the standard projected token volume. An init container creates a short-lived kubeconfig in an `emptyDir` volume which points at the in-cluster Kubernetes API endpoint and references the ServiceAccount token file.

This keeps the application independent of any operator's personal kubeconfig and preserves Kubernetes API/RBAC authorization for every request.

## Production recommendations

- Use an enterprise container registry rather than public Docker Hub pulls for the application images.
- Disable bundled MongoDB and use the customer's managed MongoDB where possible.
- Keep remediation RBAC disabled until the remediation executor has a separately reviewed permission set.
- Keep Secret access disabled unless a concrete feature requires it and the customer approves it.
- Use the organization's existing ingress, TLS, identity provider, and network policies.
- Store LangSmith credentials and database credentials in the customer's secret management system rather than Git.
- Review the exact Helm-rendered RBAC before installation.
