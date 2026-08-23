# Security Demo v2

The dashboard is intentionally security-first. It shows only the ten most actionable distinct issues, keeps the investigation button below cluster selection, and treats Trivy as a fallback/secondary source.

## 1. Create breadth of findings

```bash
kubectl apply -f deploy/security-demo/insecure-workloads.yaml
```

This fixture is intentionally insecure and is for a demo cluster only. It exercises workload privilege, host access, service-account exposure, external service exposure, and network isolation checks.

## 2. Exercise Kubescape

Make sure the Kubescape operator has continuous scanning enabled and wait for its workload scan summaries:

```bash
kubectl get workloadconfigurationscansummaries -A
```

The agent reads failed controls from the Kubernetes-native Kubescape summaries and presents them as **COMPLIANCE** findings rather than duplicating every scanner row.

## 3. Exercise Falco runtime detection

If Falco is running with its normal runtime rules, trigger a controlled demo event in a disposable pod. A common test is reading a sensitive file from a demo container:

```bash
kubectl exec -n security-demo deploy/privileged-demo -- sh -c 'cat /etc/shadow >/dev/null'
```

Then run **Investigate Cluster**. The agent samples only a few recent Falco log lines and surfaces distinct runtime alerts as **RUNTIME** findings. It does not ingest the full Falco log stream.

If your Falco configuration uses Falcosidekick, the same runtime alerts can continue to be handled by your existing forwarding pipeline; this demo only needs recent Falco pod logs.

## 4. Trivy behavior

Trivy is not the hero of this dashboard. The fast path first checks native Kubernetes posture, Kubescape and Falco. Trivy is consulted only when those sources produce fewer than three useful findings. When used, no more than two Trivy-derived issues are allowed into the top-ten hero list.

## 5. Score

The posture score starts at 100. Distinct verified findings reduce it using severity weights, then the risk is normalized by affected resources. Exposed secrets and Falco runtime alerts have explicit weights. The UI shows the score explanation and the weighted contribution chart so the rating is explainable rather than a mystery number.

## Cleanup

```bash
kubectl delete namespace security-demo
```
