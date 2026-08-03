from datetime import datetime, timezone, timedelta

import pytest
from bson.objectid import ObjectId

from backend.services import remediation_service


class FakeCollection:
    def __init__(self, docs):
        self.docs = {d["_id"]: d for d in docs}

    def find_one(self, filter):
        oid = filter.get("_id")
        if isinstance(oid, str):
            oid = ObjectId(oid)
        return self.docs.get(oid)

    def update_one(self, filter, update):
        oid = filter.get("_id")
        if isinstance(oid, str):
            oid = ObjectId(oid)
        doc = self.docs.get(oid)
        if not doc:
            return
        if "$set" in update:
            doc.update(update["$set"])



class FakeAudit:
    def create_or_update_audit(self, doc, policy_decision=None):
        pass

    def get_audit(self, remediation_id):
        return None

    def record_execution(self, doc, policy_decision):
        pass

    def record_rollback(self, doc):
        pass

class FakeDB:
    def __init__(self, remediation_doc, investigation_doc=None):
        self.remediations = FakeCollection([remediation_doc])
        self.investigations = FakeCollection([investigation_doc] if investigation_doc else [])


class FakeToolkit:
    def __init__(self, *args, **kwargs):
        pass

    def get_resource(self, kind, namespace, name):
        return {
            "success": True,
            "data": {
                "resource": {
                    "metadata": {"generation": 1},
                    "status": {"observedGeneration": 1},
                }
            },
        }

    def get_resources(self, kind, namespace=None):
        return {
            "success": True,
            "data": {
                "kind": kind,
                "namespace": namespace,
                "items": [
                    {
                        "metadata": {
                            "ownerReferences": [
                                {"kind": "Deployment", "name": "app"},
                            ],
                        },
                        "status": {
                            "phase": "Running",
                            "conditions": [
                                {"type": "Ready", "status": "True"},
                            ],
                            "containerStatuses": [
                                {"ready": True, "state": {"running": {}}},
                            ],
                        },
                    }
                ],
            },
        }

    def get_events(self, namespace=None, resource_name=None):
        return {"success": True, "data": {"namespace": namespace, "resource_name": resource_name, "items": []}}

    def get_rollout_status(self, kind, namespace, name):
        return {
            "success": True,
            "data": {
                "desired": 1,
                "ready": 1,
                "updated": 1,
                "available": 1,
                "unavailable": 0,
            },
        }

    def scale_workload(self, kind, namespace, name, replicas, dry_run=False):
        return {"success": True, "data": {"scaled": True}}

    def patch_resource(self, kind, namespace, name, patch, dry_run=False):
        return {"success": True, "data": {"patched": True}}

    def apply_resource(self, manifest, dry_run=False):
        return {"success": True, "data": {"applied": True}}

    def restart_workload(self, kind, namespace, name, dry_run=False):
        return {"success": True, "data": {"restarted": True}}

    def rollback_workload(self, kind, namespace, name, dry_run=False):
        return {"success": True, "data": {"rolled_back": True}}


class FakePolicyEngine:
    def __init__(self, *args, **kwargs):
        pass

    def validate(self, plan, diagnosis=None, toolkit=None):
        return {"allowed": True, "violations": []}


class FailingToolkit(FakeToolkit):
    def scale_workload(self, kind, namespace, name, replicas, dry_run=False):
        return {"success": False, "error": {"message": "forbidden"}}


class FailingPolicyEngine(FakePolicyEngine):
    def validate(self, plan, diagnosis=None, toolkit=None):
        return {"allowed": False, "violations": ["policy denied"]}


class FailingVerifyToolkit(FakeToolkit):
    def get_rollout_status(self, kind, namespace, name):
        return {
            "success": True,
            "data": {
                "desired": 1,
                "ready": 0,
                "updated": 1,
                "available": 0,
                "unavailable": 1,
            },
        }


def _make_doc(status="AWAITING_APPROVAL", updated_at=None):
    if updated_at is None:
        updated_at = datetime.now(timezone.utc)
    return {
        "_id": ObjectId(),
        "investigation_id": str(ObjectId()),
        "status": status,
        "updated_at": updated_at,
        "timestamps": [],
        "context": None,
        "diagnosis": {
            "affected_resources": ["deployment/default/app"],
            "evidence": [],
        },
        "plan": {
            "status": "READY",
            "risk": "MEDIUM",
            "tool": "scale_workload",
            "arguments": {
                "kind": "deployment",
                "namespace": "default",
                "name": "app",
                "replicas": 2,
            },
            "target": {"kind": "deployment", "namespace": "default", "name": "app"},
            "verification": {"type": "rollout_status", "expected": "ready"},
        },
    }


@pytest.fixture
def fake_db_factory(monkeypatch):
    def make(
        status="AWAITING_APPROVAL",
        toolkit_cls=None,
        policy_engine_cls=None,
        **overrides,
    ):
        doc = _make_doc(status=status)
        doc.update(overrides)
        db = FakeDB(doc)

        def fake_get_db():
            return db

        monkeypatch.setattr("backend.services.remediation_service.get_db", fake_get_db)
        monkeypatch.setattr("backend.services.remediation_service.K8sToolkit", toolkit_cls or FakeToolkit)
        monkeypatch.setattr("backend.services.remediation_service.PolicyEngine", policy_engine_cls or FakePolicyEngine)
        monkeypatch.setattr("backend.services.remediation_service.audit_service", FakeAudit())
        return db, doc

    return make


def test_execute_success(fake_db_factory):
    db, doc = fake_db_factory()
    remediation_id = str(doc["_id"])
    remediation_service.execute_remediation(remediation_id)

    updated = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    assert updated["status"] == "RESOLVED"
    assert updated["execution_id"] is not None
    assert updated["pre_change_state"] is not None
    assert updated["rollback_plan"] is not None
    assert updated["kubernetes_response"]["success"] is True
    assert any(t["state"] == "APPROVED" for t in updated["timestamps"])
    assert any(t["state"] == "RESOLVED" for t in updated["timestamps"])
    assert updated["verification_result"]["status"] == "RESOLVED"
    assert updated["verification_result"]["checks"]


def test_execute_verification_failure_marks_failed_with_rollback_plan(fake_db_factory, monkeypatch):
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    counter = {"ticks": 0}

    def fake_now():
        counter["ticks"] += 5
        return start + timedelta(seconds=counter["ticks"])

    monkeypatch.setattr("backend.services.remediation_service._now", fake_now)
    monkeypatch.setattr("backend.services.remediation_service.time.sleep", lambda *_: None)

    db, doc = fake_db_factory(toolkit_cls=FailingVerifyToolkit)
    remediation_id = str(doc["_id"])
    remediation_service.execute_remediation(remediation_id)

    updated = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    assert updated["status"] == "FAILED"
    assert updated["rollback_plan"] is not None
    assert updated["verification_result"]["status"] != "RESOLVED"
    assert any(c["status"] == "FAIL" for c in updated["verification_result"]["checks"])
    assert updated["error"] == "Remediation did not resolve the incident"


def test_execute_double_execution_blocked(fake_db_factory):
    db, doc = fake_db_factory(status="RESOLVED")
    remediation_id = str(doc["_id"])

    with pytest.raises(ValueError):
        remediation_service.execute_remediation(remediation_id)


def test_execute_stale_preview_fails(fake_db_factory):
    db, doc = fake_db_factory(updated_at=datetime.now(timezone.utc) - timedelta(hours=1))
    remediation_id = str(doc["_id"])

    with pytest.raises(ValueError):
        remediation_service.execute_remediation(remediation_id)

    updated = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    assert updated["status"] == "FAILED"


def test_execute_policy_violation_marks_failed(fake_db_factory):
    db, doc = fake_db_factory(policy_engine_cls=FailingPolicyEngine)
    remediation_id = str(doc["_id"])

    with pytest.raises(ValueError):
        remediation_service.execute_remediation(remediation_id)

    updated = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    assert updated["status"] == "FAILED"


def test_execute_kubernetes_rejection_marks_failed(fake_db_factory):
    db, doc = fake_db_factory(toolkit_cls=FailingToolkit)
    remediation_id = str(doc["_id"])

    with pytest.raises(ValueError):
        remediation_service.execute_remediation(remediation_id)

    updated = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    assert updated["status"] == "FAILED"
    assert "forbidden" in (updated.get("error") or "")


def test_rollback_after_failed_verification(fake_db_factory):
    pre = {"resource": {"metadata": {"generation": 1}, "spec": {"replicas": 1}}}
    rollback_plan = {
        "tool": "rollback_workload",
        "arguments": {"kind": "deployment", "namespace": "default", "name": "app"},
    }
    db, doc = fake_db_factory(
        status="FAILED",
        pre_change_state=pre,
        rollback_plan=rollback_plan,
        kubernetes_response={"success": True},
        verification_result={"status": "NOT_RESOLVED", "checks": []},
    )
    remediation_id = str(doc["_id"])

    remediation_service.rollback_remediation(remediation_id)

    updated = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    assert updated["status"] == "ROLLED_BACK"
    assert updated["rollback_execution_id"] is not None
    assert updated["rollback_response"]["success"] is True


def test_rollback_without_plan_fails(fake_db_factory):
    db, doc = fake_db_factory(
        status="FAILED",
        rollback_plan=None,
        kubernetes_response={"success": True},
        verification_result={"status": "NOT_RESOLVED", "checks": []},
    )
    remediation_id = str(doc["_id"])

    with pytest.raises(ValueError):
        remediation_service.rollback_remediation(remediation_id)

    updated = db.remediations.find_one({"_id": ObjectId(remediation_id)})
    assert updated["status"] == "ROLLBACK_FAILED"
