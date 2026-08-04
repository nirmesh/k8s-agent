import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any

from backend.core.logging import logger
from backend.evidence.security.model import SecurityEvidence, SecurityFinding
from backend.evidence.security.provider import SecurityProvider


class TrivyAdapter(SecurityProvider):
    """Trivy scanner adapter. Expects Trivy JSON report payload.

    Supports:
      - path to a JSON file
      - raw JSON string
      - parsed Python dict/list
    """

    def __init__(self, source: Any | None = None, binary: str | None = "trivy"):
        self._source = source
        self._binary = binary or "trivy"

    @property
    def name(self) -> str:
        return "trivy"

    def _run_trivy(self, args: list[str]) -> dict[str, Any] | None:
        if shutil.which(self._binary) is None:
            logger.warning(f"Trivy binary '{self._binary}' not found in PATH")
            return None
        cmd = [self._binary, "-f", "json", "--quiet"] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300,
            )
            return json.loads(result.stdout)
        except Exception as exc:
            logger.warning(f"Trivy command failed: {exc}")
            return None

    def _load(self, query: dict[str, Any] | None) -> list[dict[str, Any]]:
        source = (query or {}).get("source") if isinstance(query, dict) else None
        source = source or self._source
        if source is None:
            return []
        if isinstance(source, str):
            try:
                data = json.loads(source)
            except json.JSONDecodeError:
                with open(source, "r", encoding="utf-8") as f:
                    data = json.load(f)
        elif isinstance(source, bytes):
            data = json.loads(source.decode("utf-8"))
        else:
            data = source
        if isinstance(data, dict):
            return [data]
        return data if isinstance(data, list) else []

    def collect(self, query: dict[str, Any] | None = None) -> list[SecurityEvidence]:
        query = query or {}
        if "source" in query or self._source is not None:
            reports = self._load(query)
            return self._parse_reports(reports)

        resource = query.get("resource") or "cluster"
        category = query.get("category")

        if resource == "cluster":
            return self.scan_cluster()
        if resource.startswith("image/"):
            image = resource[len("image/"):]
            if category == "sbom":
                return self.get_sbom(image)
            return self.scan_image(image)
        parts = resource.split("/")
        if len(parts) == 2 and parts[0].lower() == "namespace":
            return self.scan_namespace(parts[1])
        if len(parts) == 3:
            kind, namespace, name = parts
            if category == "sbom":
                return self.get_sbom(f"{kind}/{namespace}/{name}")
            return self.scan_workload(kind, namespace, name)
        return []

    def scan_cluster(self) -> list[SecurityEvidence]:
        data = self._run_trivy(["k8s", "cluster"])
        return self._parse_reports([data]) if data else []

    def scan_namespace(self, namespace: str) -> list[SecurityEvidence]:
        data = self._run_trivy(["k8s", "--namespace", namespace])
        return self._parse_reports([data]) if data else []

    def scan_workload(self, kind: str, namespace: str, name: str) -> list[SecurityEvidence]:
        data = self._run_trivy([
            "k8s",
            "--namespace",
            namespace,
            f"--include-kinds={kind}",
            f"--resource-name={name}",
        ])
        return self._parse_reports([data]) if data else []

    def scan_image(self, image: str) -> list[SecurityEvidence]:
        data = self._run_trivy(["image", image])
        return self._parse_reports([data]) if data else []

    def scan_manifest(self, manifest: str | dict[str, Any] | list[Any]) -> list[SecurityEvidence]:
        path: str
        temp_path: str | None = None
        if isinstance(manifest, (dict, list)):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as f:
                json.dump(manifest, f)
                path = f.name
                temp_path = path
        else:
            path = str(manifest)
        try:
            data = self._run_trivy(["config", path])
            return self._parse_reports([data]) if data else []
        finally:
            if temp_path:
                os.unlink(temp_path)

    def get_sbom(self, image: str) -> list[SecurityEvidence]:
        data = self._run_trivy(["sbom", image, "--format", "json"])
        if data is None:
            return []
        return [
            SecurityEvidence(
                provider=self.name,
                type="security",
                resource=f"image/{image}",
                timestamp=datetime.now(timezone.utc),
                confidence=1.0,
                severity=None,
                payload={
                    "category": "sbom",
                    "artifact": image,
                    "bom_format": data.get("bomFormat"),
                    "components": data.get("components", []),
                    "dependencies": data.get("dependencies", []),
                },
            )
        ]

    def _parse_reports(
        self, reports: list[dict[str, Any]]
    ) -> list[SecurityEvidence]:
        evidence: list[SecurityEvidence] = []
        for report in reports:
            # Trivy k8s reports expose Resources, each with Results.
            for resource in report.get("Resources") or []:
                target = self._resource_target(resource)
                evidence.extend(self._parse_results(target, resource.get("Results") or []))
            # Filesystem / image reports expose top-level Results.
            target = report.get("Target", "unknown")
            evidence.extend(self._parse_results(target, report.get("Results") or []))
        return evidence

    def _parse_results(
        self, default_target: str, results: list[dict[str, Any]]
    ) -> list[SecurityEvidence]:
        evidence: list[SecurityEvidence] = []
        for result in results:
            target = result.get("Target") or default_target
            for vuln in result.get("Vulnerabilities") or []:
                evidence.append(self._make_vuln_evidence(target, vuln))
            for misconf in result.get("Misconfigurations") or []:
                evidence.append(self._make_misconf_evidence(target, misconf))
            for secret in result.get("Secrets") or []:
                evidence.append(self._make_secret_evidence(target, secret))
        return evidence

    def _resource_target(self, resource: dict[str, Any]) -> str:
        kind = resource.get("Kind", "")
        namespace = resource.get("Namespace", "")
        name = resource.get("Name", "")
        if kind and namespace:
            return f"{kind}/{namespace}/{name}"
        if kind:
            return f"{kind}/{namespace or '-'}/{name or '-'}"
        return resource.get("Target", "unknown")

    def _make_vuln_evidence(
        self, target: str, vuln: dict[str, Any]
    ) -> SecurityEvidence:
        finding = SecurityFinding(
            category="vulnerability",
            resource=f"image/{target}" if target.startswith("image/") else f"image/{target}",
            finding=f"{vuln.get('VulnerabilityID', 'unknown')}: {vuln.get('Title', '')}",
            description=vuln.get("Description", ""),
            severity=self._normalize_severity(vuln.get("Severity", "UNKNOWN")),
            confidence=1.0,
            remediation=self._remediation(vuln),
            rule_id=None,
            cve_id=vuln.get("VulnerabilityID"),
        )
        return SecurityEvidence(
            provider=self.name,
            type="security",
            resource=finding.resource,
            timestamp=datetime.now(timezone.utc),
            confidence=finding.confidence,
            severity=finding.severity,
            payload=finding,
        )

    def _make_misconf_evidence(
        self, target: str, misconf: dict[str, Any]
    ) -> SecurityEvidence:
        finding = SecurityFinding(
            category="misconfiguration",
            resource=target,
            finding=f"{misconf.get('ID', 'unknown')}: {misconf.get('Title', '')}",
            description=misconf.get("Description") or misconf.get("Message", ""),
            severity=self._normalize_severity(misconf.get("Severity", "UNKNOWN")),
            confidence=1.0,
            remediation=misconf.get("PrimaryURL") or misconf.get("Resolution", ""),
            rule_id=misconf.get("ID"),
            cve_id=None,
        )
        return SecurityEvidence(
            provider=self.name,
            type="security",
            resource=finding.resource,
            timestamp=datetime.now(timezone.utc),
            confidence=finding.confidence,
            severity=finding.severity,
            payload=finding,
        )

    def _make_secret_evidence(
        self, target: str, secret: dict[str, Any]
    ) -> SecurityEvidence:
        finding = SecurityFinding(
            category="secret",
            resource=target,
            finding=f"{secret.get('RuleID', 'unknown')}: {secret.get('Title', '')}",
            description=secret.get("Match", ""),
            severity=self._normalize_severity(secret.get("Severity", "UNKNOWN")),
            confidence=1.0,
            remediation=None,
            rule_id=secret.get("RuleID"),
            cve_id=None,
        )
        return SecurityEvidence(
            provider=self.name,
            type="security",
            resource=finding.resource,
            timestamp=datetime.now(timezone.utc),
            confidence=finding.confidence,
            severity=finding.severity,
            payload=finding,
        )

    def _normalize_severity(self, severity: str) -> str:
        return str(severity).upper() if severity else "UNKNOWN"

    def _remediation(self, vuln: dict[str, Any]) -> str | None:
        parts = []
        if vuln.get("FixedVersion"):
            parts.append(f"Upgrade to {vuln['FixedVersion']}.")
        if vuln.get("PrimaryURL"):
            parts.append(vuln["PrimaryURL"])
        return " ".join(parts) if parts else None
