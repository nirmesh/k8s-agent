# Security demo fixtures

These manifests intentionally create **workload-level** security problems so the dashboard can demonstrate breadth without changing the Kubernetes control plane.

They exercise:

- privileged container
- explicit privilege escalation
- root container
- hostPath filesystem access
- hostNetwork
- automatically mounted service-account token
- externally exposed NodePort
- namespace with no NetworkPolicy
- a clearly labelled demo-only Kubernetes Secret

## Run

```bash
kubectl apply -f deploy/security-demo/insecure-workloads.yaml
```

Then run **Investigate Cluster**. The security panel should produce distinct findings instead of repeating one Trivy CVE.

## Cleanup

```bash
kubectl delete namespace security-demo
```

**Important:** this is intentionally insecure demo configuration. Do not apply it to a production cluster.

The application does **not** modify etcd or the Kubernetes control plane for this demo. Control-plane/datastore findings are reported only when the live cluster configuration provides evidence for them.
