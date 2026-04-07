"""Lightweight tests for auth_agent: output structure and detection."""
import pytest
from src.agents.auth_agent import run_agent, build_incident_output


# Minimal mock records that trigger one incident (repeated_authentication_failure)
MOCK_LOGS = [
    {
        "line_id": "linux_1",
        "dataset": "linux",
        "timestamp_iso": "2015-06-14T15:16:01Z",
        "timestamp_epoch": 1434294961000,
        "message": "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=192.168.1.1",
        "component": "sshd(pam_unix)",
    },
    {
        "line_id": "linux_2",
        "dataset": "linux",
        "timestamp_iso": "2015-06-14T15:16:02Z",
        "timestamp_epoch": 1434294962000,
        "message": "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=192.168.1.1",
        "component": "sshd(pam_unix)",
    },
]


def test_auth_agent_output_structure():
    """Run detection on mock logs and assert output has required fields."""
    incidents = run_agent(MOCK_LOGS)
    assert len(incidents) >= 1
    rec = incidents[0]
    assert "agent" in rec
    assert rec["agent"] == "auth_agent"
    assert "event_category" in rec
    assert "severity" in rec
    assert "confidence" in rec
    assert rec["event_category"] in (
        "repeated_authentication_failure",
        "invalid_user_attempt",
        "successful_auth_after_failures",
        "suspicious_login_burst",
    )
    assert rec["severity"] in ("high", "medium", "low")
    assert 0.0 <= rec["confidence"] <= 1.0


def test_build_incident_output_has_required_fields():
    """Build one incident dict and assert required keys."""
    records = [{**m, "_actor_key": "192.168.1.1"} for m in MOCK_LOGS]
    out = build_incident_output(
        records,
        event_category="repeated_authentication_failure",
        severity="high",
        summary="test",
        confidence=0.8,
    )
    assert out["agent"] == "auth_agent"
    assert out["event_category"] == "repeated_authentication_failure"
    assert out["severity"] == "high"
    assert out["confidence"] == 0.8
