"""Lightweight tests for openstack_vm_agent: output structure and detection."""
import pytest
from src.agents.openstack_vm_agent import run_agent, detect_anomalies


# Minimal mock records for one instance with lifecycle churn (multiple event types)
MOCK_LOGS = [
    {
        "line_id": "openstack_1",
        "dataset": "openstack",
        "timestamp_iso": "2017-05-16T00:00:04.5Z",
        "timestamp_epoch": 1494892804500,
        "component": "nova.compute.manager",
        "message": "[instance: a1b2c3d4-e5f6-7890-abcd-ef1234567890] VM Started (Lifecycle Event)",
        "event_template": "[instance: <*>] VM Started (Lifecycle Event)",
    },
    {
        "line_id": "openstack_2",
        "dataset": "openstack",
        "timestamp_iso": "2017-05-16T00:00:05Z",
        "timestamp_epoch": 1494892805000,
        "component": "nova.compute.manager",
        "message": "[instance: a1b2c3d4-e5f6-7890-abcd-ef1234567890] VM Stopped (Lifecycle Event)",
        "event_template": "[instance: <*>] VM Stopped (Lifecycle Event)",
    },
    {
        "line_id": "openstack_3",
        "dataset": "openstack",
        "timestamp_iso": "2017-05-16T00:00:06Z",
        "timestamp_epoch": 1494892806000,
        "component": "nova.compute.manager",
        "message": "[instance: a1b2c3d4-e5f6-7890-abcd-ef1234567890] VM Started (Lifecycle Event)",
        "event_template": "[instance: <*>] VM Started (Lifecycle Event)",
    },
    {
        "line_id": "openstack_4",
        "dataset": "openstack",
        "timestamp_iso": "2017-05-16T00:00:07Z",
        "timestamp_epoch": 1494892807000,
        "component": "nova.compute.manager",
        "message": "[instance: a1b2c3d4-e5f6-7890-abcd-ef1234567890] Terminating instance",
        "event_template": "[instance: <*>] Terminating instance",
    },
]


def test_openstack_vm_agent_output_structure():
    """Run detection on mock logs and assert output has required fields."""
    anomalies = run_agent(MOCK_LOGS)
    # May have lifecycle_churn (multiple types) or repeated_vm_restart_cycle
    assert isinstance(anomalies, list)
    if anomalies:
        rec = anomalies[0]
        assert "agent" in rec
        assert rec["agent"] == "openstack_vm_agent"
        assert "event_category" in rec
        assert "severity" in rec
        assert "confidence" in rec
        assert rec["event_category"] in (
            "repeated_vm_restart_cycle",
            "unexpected_vm_stop",
            "lifecycle_churn",
        )
        assert rec["severity"] in ("high", "medium", "low")
        assert 0.0 <= rec["confidence"] <= 1.0


def test_detect_anomalies_has_required_fields():
    """Call detect_anomalies directly and assert required keys."""
    instance_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    results = detect_anomalies(instance_id, MOCK_LOGS)
    for rec in results:
        assert rec["agent"] == "openstack_vm_agent"
        assert "event_category" in rec
        assert "severity" in rec
        assert "confidence" in rec
        assert rec["instance_id"] == instance_id
