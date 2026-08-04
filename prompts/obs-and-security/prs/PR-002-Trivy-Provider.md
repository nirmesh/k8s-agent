# PR-002 Trivy Provider

Implement:
- scan_cluster()
- scan_namespace()
- scan_workload()
- scan_image()
- scan_manifest()
- get_sbom()

Normalize Trivy output to SecurityEvidence.
Never expose raw Trivy JSON.
