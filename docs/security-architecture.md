# Security architecture

AI-K9s treats security as a normalized evidence domain, not as a collection of scanner UIs.

## Layers

- `posture`: static configuration and Kubernetes security posture
- `attack_surface`: externally reachable or discoverable attack paths
- `supply_chain`: images, packages and SBOM provenance
- `runtime`: behavior observed while workloads execute
- `compliance`: benchmark/framework/control results

## Domains

- workload
- cluster
- control_plane
- identity
- network
- supply_chain
- runtime
- compliance
- secrets

## Providers

Providers implement `SecurityProvider` and return normalized `SecurityEvidence`. The registry hides scanner-specific output from the investigator.

Current providers:

- Trivy adapter
- Falco adapter
- Kubescape adapter
- Kubernetes-native posture adapter

Planned providers:

- kube-bench
- kube-hunter
- Syft
- Grype
- Sonobuoy

## Product packaging rule

Only the Kubernetes-native posture checks are required for the core product. External scanners should be optional Helm components, controlled by values such as `security.providers.<provider>.enabled` and `security.providers.<provider>.install`.

The distinction matters:

- `enabled`: AI-K9s consumes the provider's evidence.
- `install`: Helm installs/manages the provider in the target cluster.

A customer that already operates Trivy/Falco/etc. can set `install=false` and point AI-K9s at the existing source. A small installation can start with posture only.
