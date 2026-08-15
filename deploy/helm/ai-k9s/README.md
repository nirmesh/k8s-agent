# AI-K9s Helm Chart

This chart packages the current AI-K9s investigation stack for Kubernetes. The production default is read-only cluster investigation through a dedicated ServiceAccount and ClusterRole. The application talks to the Kubernetes API through the Python Kubernetes client; it does not require `kubectl` inside the application container.

## Default security posture

- Dedicated ServiceAccount: enabled
- Cluster-wide read-only RBAC: enabled
- Secret data access: disabled
- Remediation write permissions: disabled
- LangGraph Studio: disabled
- MongoDB: enabled for a simple first deployment; use an external MongoDB in production when preferred

## Feature toggles

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

These are explicit Helm enable/disable switches. Pod metadata can also be extended with `commonLabels` and `podLabels`.

## Install

Build and publish the backend and frontend images to a registry reachable by the target cluster, then override the image repositories and the Ollama endpoint:

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

For an external MongoDB:

```bash
helm upgrade --install ai-k9s ./deploy/helm/ai-k9s \
  --namespace ai-k9s \
  --create-namespace \
  --set features.mongodb.enabled=false \
  --set backend.env.mongodbUrl='mongodb://USER:PASSWORD@mongo.example:27017/ai_kubernetes_agent'
```

In a production environment, provide credentials through your organization's secret-management process instead of committing credentials to a values file.

## Verify RBAC

Get the actual ServiceAccount name created by the release:

```bash
SA=$(kubectl get sa -n ai-k9s -l app.kubernetes.io/instance=ai-k9s -o jsonpath='{.items[0].metadata.name}')
```

Then test the important boundaries:

```bash
kubectl auth can-i get pods --all-namespaces --as=system:serviceaccount:ai-k9s:$SA
kubectl auth can-i patch deployments --all-namespaces --as=system:serviceaccount:ai-k9s:$SA
kubectl auth can-i get secrets --all-namespaces --as=system:serviceaccount:ai-k9s:$SA
```

The expected default result is:

- pod read: yes
- deployment patch: no
- secret read: no

## Read-only versus remediation

Do not enable remediation for the current read-only investigation release unless the customer explicitly approves those permissions:

```bash
--set rbac.remediation.enabled=true
```

When enabled, the chart adds a narrow set of patch/update permissions for selected workload and networking resources. Review the resulting RBAC before applying it in a production cluster.

## Kubernetes authentication

The backend uses the Pod's ServiceAccount token and cluster CA to create an in-cluster kubeconfig in an ephemeral volume. No administrator's `~/.kube/config` is required in the customer deployment.

## Notes

The separate LangGraph development server used by local Studio is intentionally not deployed by default. The application backend invokes the LangGraph graph in-process for the production request path.
