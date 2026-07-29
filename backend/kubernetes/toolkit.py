import os
import sys
from datetime import datetime, timezone
from typing import Any

from backend.core.config import settings
from backend.core.logging import logger

# The local `backend/kubernetes` package shadows the installed `kubernetes`
# client when the backend workdir is on sys.path. Remove the backend package
# root (and cwd entries) temporarily so `import kubernetes` resolves to the
# installed Python client instead of the local subpackage.
_backend_pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_local_kubernetes_shadows = {_backend_pkg_dir, "", ".", os.getcwd()}
_original_path = sys.path.copy()
for entry in list(_original_path):
    if entry in _local_kubernetes_shadows:
        sys.path.remove(entry)
try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
finally:
    sys.path = _original_path

RESOURCE_MAP = {
    "pod": {
        "api": client.CoreV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_pod",
        "list_all": "list_pod_for_all_namespaces",
        "read": "read_namespaced_pod",
        "patch": "patch_namespaced_pod",
        "create": "create_namespaced_pod",
    },
    "service": {
        "api": client.CoreV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_service",
        "list_all": "list_service_for_all_namespaces",
        "read": "read_namespaced_service",
        "patch": "patch_namespaced_service",
        "create": "create_namespaced_service",
    },
    "endpoints": {
        "api": client.CoreV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_endpoints",
        "list_all": "list_endpoints_for_all_namespaces",
        "read": "read_namespaced_endpoints",
        "patch": "patch_namespaced_endpoints",
        "create": "create_namespaced_endpoints",
    },
    "configmap": {
        "api": client.CoreV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_config_map",
        "list_all": "list_config_map_for_all_namespaces",
        "read": "read_namespaced_config_map",
        "patch": "patch_namespaced_config_map",
        "create": "create_namespaced_config_map",
    },
    "secret": {
        "api": client.CoreV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_secret",
        "list_all": "list_secret_for_all_namespaces",
        "read": "read_namespaced_secret",
        "patch": "patch_namespaced_secret",
        "create": "create_namespaced_secret",
    },
    "event": {
        "api": client.CoreV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_event",
        "list_all": "list_event_for_all_namespaces",
        "read": "read_namespaced_event",
        "patch": "patch_namespaced_event",
        "create": "create_namespaced_event",
    },
    "persistentvolumeclaim": {
        "api": client.CoreV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_persistent_volume_claim",
        "list_all": "list_persistent_volume_claim_for_all_namespaces",
        "read": "read_namespaced_persistent_volume_claim",
        "patch": "patch_namespaced_persistent_volume_claim",
        "create": "create_namespaced_persistent_volume_claim",
    },
    "serviceaccount": {
        "api": client.CoreV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_service_account",
        "list_all": "list_service_account_for_all_namespaces",
        "read": "read_namespaced_service_account",
        "patch": "patch_namespaced_service_account",
        "create": "create_namespaced_service_account",
    },
    "node": {
        "api": client.CoreV1Api,
        "namespaced": False,
        "list_all": "list_node",
        "read": "read_node",
        "patch": "patch_node",
        "create": "create_node",
    },
    "namespace": {
        "api": client.CoreV1Api,
        "namespaced": False,
        "list_all": "list_namespace",
        "read": "read_namespace",
        "patch": "patch_namespace",
        "create": "create_namespace",
    },
    "persistentvolume": {
        "api": client.CoreV1Api,
        "namespaced": False,
        "list_all": "list_persistent_volume",
        "read": "read_persistent_volume",
        "patch": "patch_persistent_volume",
        "create": "create_persistent_volume",
    },
    "deployment": {
        "api": client.AppsV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_deployment",
        "list_all": "list_deployment_for_all_namespaces",
        "read": "read_namespaced_deployment",
        "patch": "patch_namespaced_deployment",
        "create": "create_namespaced_deployment",
    },
    "statefulset": {
        "api": client.AppsV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_stateful_set",
        "list_all": "list_stateful_set_for_all_namespaces",
        "read": "read_namespaced_stateful_set",
        "patch": "patch_namespaced_stateful_set",
        "create": "create_namespaced_stateful_set",
    },
    "daemonset": {
        "api": client.AppsV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_daemon_set",
        "list_all": "list_daemon_set_for_all_namespaces",
        "read": "read_namespaced_daemon_set",
        "patch": "patch_namespaced_daemon_set",
        "create": "create_namespaced_daemon_set",
    },
    "replicaset": {
        "api": client.AppsV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_replica_set",
        "list_all": "list_replica_set_for_all_namespaces",
        "read": "read_namespaced_replica_set",
        "patch": "patch_namespaced_replica_set",
        "create": "create_namespaced_replica_set",
    },
    "job": {
        "api": client.BatchV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_job",
        "list_all": "list_job_for_all_namespaces",
        "read": "read_namespaced_job",
        "patch": "patch_namespaced_job",
        "create": "create_namespaced_job",
    },
    "cronjob": {
        "api": client.BatchV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_cron_job",
        "list_all": "list_cron_job_for_all_namespaces",
        "read": "read_namespaced_cron_job",
        "patch": "patch_namespaced_cron_job",
        "create": "create_namespaced_cron_job",
    },
    "ingress": {
        "api": client.NetworkingV1Api,
        "namespaced": True,
        "list_namespaced": "list_namespaced_ingress",
        "list_all": "list_ingress_for_all_namespaces",
        "read": "read_namespaced_ingress",
        "patch": "patch_namespaced_ingress",
        "create": "create_namespaced_ingress",
    },
}

SCALABLE_KINDS = {"deployment", "statefulset", "replicaset", "replicationcontroller"}
RESTARTABLE_KINDS = {"deployment", "statefulset", "daemonset", "replicaset"}


class K8sToolkit:
    """Generic Kubernetes API tool layer.

    All public methods return a structured JSON result:
    {
        "success": bool,
        "tool": str,
        "data": Any,
        "error": { "code": str, "message": str } | None
    }
    """

    def __init__(
        self,
        context: str | None = None,
        config_path: str | None = None,
        _api_client: Any | None = None,
    ):
        self.context = context
        self.config_path = config_path or settings.kubeconfig_path
        self.config_path = os.path.expandvars(os.path.expanduser(self.config_path))
        self.api_client = _api_client
        self._load()

    def _load(self) -> None:
        if self.api_client is not None:
            return
        try:
            self.api_client = config.new_client_from_config(
                config_file=self.config_path,
                context=self.context,
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to load kubeconfig {self.config_path}: {exc}") from exc

    def _api(self, api_class: type):
        return api_class(api_client=self.api_client)

    def _call(self, api_class: type, method: str, *args, **kwargs):
        api = self._api(api_class)
        return getattr(api, method)(*args, **kwargs)

    @staticmethod
    def _serialize(value: Any) -> Any:
        if hasattr(value, "to_dict"):
            return value.to_dict()
        if isinstance(value, list):
            return [K8sToolkit._serialize(v) for v in value]
        if isinstance(value, dict):
            return {k: K8sToolkit._serialize(v) for k, v in value.items()}
        return value

    def _ok(self, tool: str, data: Any) -> dict:
        return {"success": True, "tool": tool, "data": data, "error": None}

    def _err(self, tool: str, code: str, message: str, status: int | None = None) -> dict:
        error = {"code": code, "message": message}
        if status is not None:
            error["status"] = status
        return {"success": False, "tool": tool, "data": None, "error": error}

    @staticmethod
    def _kind_key(kind: str) -> str:
        return kind.lower()

    def _meta(self, kind: str) -> dict:
        key = self._kind_key(kind)
        meta = RESOURCE_MAP.get(key)
        if not meta:
            raise ValueError(f"Unsupported resource kind: {kind}")
        return meta

    def _namespaced_kwargs(self, meta: dict, namespace: str | None, name: str | None = None) -> dict:
        kwargs: dict[str, Any] = {}
        if meta["namespaced"]:
            if not namespace:
                raise ValueError(f"{kind_title(meta['read'])} requires a namespace")
            kwargs["namespace"] = namespace
        if name:
            kwargs["name"] = name
        return kwargs

    def get_resources(self, kind: str, namespace: str | None = None) -> dict:
        try:
            meta = self._meta(kind)
            method = meta["list_namespaced"] if (meta["namespaced"] and namespace) else meta["list_all"]
            result = self._call(meta["api"], method, **({"namespace": namespace} if (meta["namespaced"] and namespace) else {}))
            items = [self._serialize(i) for i in (getattr(result, "items", []) or [])]
            return self._ok("get_resources", {"kind": kind, "namespace": namespace, "items": items})
        except ValueError as exc:
            return self._err("get_resources", "UNSUPPORTED_KIND", str(exc))
        except ApiException as exc:
            return self._err("get_resources", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("get_resources failed")
            return self._err("get_resources", "INTERNAL_ERROR", str(exc))

    def get_resource(self, kind: str, namespace: str | None, name: str) -> dict:
        try:
            meta = self._meta(kind)
            kwargs = self._namespaced_kwargs(meta, namespace, name)
            result = self._call(meta["api"], meta["read"], **kwargs)
            return self._ok("get_resource", {"kind": kind, "resource": self._serialize(result)})
        except ValueError as exc:
            return self._err("get_resource", "VALIDATION_ERROR", str(exc))
        except ApiException as exc:
            return self._err("get_resource", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("get_resource failed")
            return self._err("get_resource", "INTERNAL_ERROR", str(exc))

    def get_events(self, namespace: str | None = None, resource_name: str | None = None) -> dict:
        try:
            kwargs: dict[str, Any] = {}
            if namespace:
                method = "list_namespaced_event"
                kwargs["namespace"] = namespace
            else:
                method = "list_event_for_all_namespaces"
            if resource_name:
                kwargs["field_selector"] = f"involvedObject.name={resource_name}"
            result = self._call(client.CoreV1Api, method, **kwargs)
            items = [self._serialize(i) for i in (getattr(result, "items", []) or [])]
            return self._ok("get_events", {"namespace": namespace, "resource_name": resource_name, "items": items})
        except ApiException as exc:
            return self._err("get_events", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("get_events failed")
            return self._err("get_events", "INTERNAL_ERROR", str(exc))

    def get_logs(self, namespace: str, pod: str, container: str | None = None, tail_lines: int = 100) -> dict:
        try:
            kwargs: dict[str, Any] = {"name": pod, "namespace": namespace}
            if container:
                kwargs["container"] = container
            kwargs["tail_lines"] = tail_lines
            logs = self._call(client.CoreV1Api, "read_namespaced_pod_log", **kwargs)
            return self._ok("get_logs", {"pod": pod, "namespace": namespace, "container": container, "tail_lines": tail_lines, "logs": logs})
        except ApiException as exc:
            return self._err("get_logs", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("get_logs failed")
            return self._err("get_logs", "INTERNAL_ERROR", str(exc))

    def get_owner(self, kind: str, namespace: str | None, name: str) -> dict:
        try:
            resource = self.get_resource(kind, namespace, name)
            if not resource["success"]:
                return resource
            refs = resource["data"]["resource"].get("metadata", {}).get("owner_references") or []
            owners = []
            for ref in refs:
                owner_kind = ref.get("kind", "")
                owner_name = ref.get("name", "")
                if not owner_kind or not owner_name:
                    continue
                owner = self.get_resource(owner_kind, namespace, owner_name)
                if owner["success"]:
                    owners.append(owner["data"]["resource"])
            return self._ok("get_owner", {"kind": kind, "name": name, "owners": owners})
        except ApiException as exc:
            return self._err("get_owner", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("get_owner failed")
            return self._err("get_owner", "INTERNAL_ERROR", str(exc))

    def get_rollout_status(self, kind: str, namespace: str | None, name: str) -> dict:
        try:
            meta = self._meta(kind)
            if kind.lower() not in {"deployment", "statefulset", "daemonset", "replicaset"}:
                return self._err("get_rollout_status", "UNSUPPORTED_KIND", f"Rollout status not supported for {kind}")
            result = self._call(meta["api"], meta["read"], **self._namespaced_kwargs(meta, namespace, name))
            data = self._serialize(result)
            status = self._extract_rollout(data, kind)
            status["kind"] = kind
            status["name"] = name
            status["namespace"] = namespace
            return self._ok("get_rollout_status", status)
        except ValueError as exc:
            return self._err("get_rollout_status", "VALIDATION_ERROR", str(exc))
        except ApiException as exc:
            return self._err("get_rollout_status", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("get_rollout_status failed")
            return self._err("get_rollout_status", "INTERNAL_ERROR", str(exc))

    @staticmethod
    def _extract_rollout(data: dict, kind: str) -> dict:
        spec = data.get("spec", {})
        st = data.get("status", {})
        key = kind.lower()
        if key in {"deployment", "statefulset", "replicaset"}:
            return {
                "desired": spec.get("replicas", 0),
                "ready": st.get("ready_replicas", 0),
                "updated": st.get("updated_replicas", 0) if key != "replicaset" else None,
                "available": st.get("available_replicas", 0),
                "unavailable": st.get("unavailable_replicas", 0) if key == "deployment" else None,
            }
        if key == "daemonset":
            return {
                "desired": st.get("desired_number_scheduled", 0),
                "ready": st.get("number_ready", 0),
                "updated": st.get("updated_number_scheduled", 0),
                "available": st.get("number_available", 0),
                "unavailable": st.get("number_unavailable", 0),
            }
        return {}

    def _dry_run_kwarg(self, dry_run: bool):
        return ["All"] if dry_run else None

    def patch_resource(self, kind: str, namespace: str | None, name: str, patch: dict, dry_run: bool = False) -> dict:
        try:
            meta = self._meta(kind)
            kwargs = self._namespaced_kwargs(meta, namespace, name)
            kwargs["body"] = patch
            kwargs["dry_run"] = self._dry_run_kwarg(dry_run)
            result = self._call(meta["api"], meta["patch"], **kwargs)
            return self._ok("patch_resource", {"kind": kind, "name": name, "dry_run": dry_run, "resource": self._serialize(result)})
        except ValueError as exc:
            return self._err("patch_resource", "VALIDATION_ERROR", str(exc))
        except ApiException as exc:
            return self._err("patch_resource", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("patch_resource failed")
            return self._err("patch_resource", "INTERNAL_ERROR", str(exc))

    def apply_resource(self, manifest: dict, dry_run: bool = False) -> dict:
        try:
            kind = manifest.get("kind", "").lower()
            name = manifest.get("metadata", {}).get("name")
            namespace = manifest.get("metadata", {}).get("namespace")
            if not kind or not name:
                return self._err("apply_resource", "VALIDATION_ERROR", "manifest must include kind and metadata.name")
            meta = self._meta(kind)
            if meta["namespaced"] and not namespace:
                return self._err("apply_resource", "VALIDATION_ERROR", f"{kind} requires metadata.namespace")

            existing = self.get_resource(kind, namespace, name)
            dry = self._dry_run_kwarg(dry_run)
            kwargs: dict[str, Any] = {"body": manifest, "dry_run": dry}
            if meta["namespaced"]:
                kwargs["namespace"] = namespace

            if existing["success"]:
                patch_kwargs = self._namespaced_kwargs(meta, namespace, name)
                patch_kwargs["body"] = manifest
                patch_kwargs["dry_run"] = dry
                result = self._call(meta["api"], meta["patch"], **patch_kwargs)
                action = "patched"
            elif existing.get("error", {}).get("status") == 404:
                result = self._call(meta["api"], meta["create"], **kwargs)
                action = "created"
            else:
                return existing

            return self._ok("apply_resource", {"kind": kind, "name": name, "action": action, "dry_run": dry_run, "resource": self._serialize(result)})
        except ValueError as exc:
            return self._err("apply_resource", "VALIDATION_ERROR", str(exc))
        except ApiException as exc:
            return self._err("apply_resource", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("apply_resource failed")
            return self._err("apply_resource", "INTERNAL_ERROR", str(exc))

    def restart_workload(self, kind: str, namespace: str | None, name: str, dry_run: bool = False) -> dict:
        try:
            key = self._kind_key(kind)
            if key not in RESTARTABLE_KINDS:
                return self._err("restart_workload", "UNSUPPORTED_KIND", f"Restart not supported for {kind}")
            restarted_at = datetime.now(timezone.utc).isoformat()
            patch = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": restarted_at
                            }
                        }
                    }
                }
            }
            meta = self._meta(kind)
            kwargs = self._namespaced_kwargs(meta, namespace, name)
            kwargs["body"] = patch
            kwargs["dry_run"] = self._dry_run_kwarg(dry_run)
            result = self._call(meta["api"], meta["patch"], **kwargs)
            return self._ok("restart_workload", {"kind": kind, "name": name, "restarted_at": restarted_at, "dry_run": dry_run, "resource": self._serialize(result)})
        except ValueError as exc:
            return self._err("restart_workload", "VALIDATION_ERROR", str(exc))
        except ApiException as exc:
            return self._err("restart_workload", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("restart_workload failed")
            return self._err("restart_workload", "INTERNAL_ERROR", str(exc))

    def rollback_workload(self, kind: str, namespace: str | None, name: str, dry_run: bool = False) -> dict:
        try:
            if self._kind_key(kind) != "deployment":
                return self._err("rollback_workload", "UNSUPPORTED_KIND", "Rollback is only supported for Deployments")
            if not namespace:
                return self._err("rollback_workload", "VALIDATION_ERROR", "Deployment rollback requires a namespace")
            body = {"kind": "DeploymentRollback", "apiVersion": "apps/v1", "name": name}
            result = self._call(client.AppsV1Api, "create_namespaced_deployment_rollback", name, namespace, body=body, dry_run=self._dry_run_kwarg(dry_run))
            return self._ok("rollback_workload", {"kind": kind, "name": name, "dry_run": dry_run, "rollback": self._serialize(result)})
        except ApiException as exc:
            return self._err("rollback_workload", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("rollback_workload failed")
            return self._err("rollback_workload", "INTERNAL_ERROR", str(exc))

    def scale_workload(self, kind: str, namespace: str | None, name: str, replicas: int, dry_run: bool = False) -> dict:
        try:
            key = self._kind_key(kind)
            if key not in SCALABLE_KINDS:
                return self._err("scale_workload", "UNSUPPORTED_KIND", f"Scale not supported for {kind}")
            meta = self._meta(kind)
            patch = {"spec": {"replicas": replicas}}
            kwargs = self._namespaced_kwargs(meta, namespace, name)
            kwargs["body"] = patch
            kwargs["dry_run"] = self._dry_run_kwarg(dry_run)
            result = self._call(meta["api"], meta["patch"], **kwargs)
            return self._ok("scale_workload", {"kind": kind, "name": name, "replicas": replicas, "dry_run": dry_run, "resource": self._serialize(result)})
        except ValueError as exc:
            return self._err("scale_workload", "VALIDATION_ERROR", str(exc))
        except ApiException as exc:
            return self._err("scale_workload", "K8S_ERROR", exc.reason or str(exc), status=exc.status)
        except Exception as exc:
            logger.exception("scale_workload failed")
            return self._err("scale_workload", "INTERNAL_ERROR", str(exc))


def kind_title(method_name: str) -> str:
    return method_name.split("_")[-1].capitalize()
