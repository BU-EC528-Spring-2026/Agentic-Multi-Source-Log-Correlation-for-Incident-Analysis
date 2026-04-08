from src.agents.linux_system_agent import run_agent


def test_linux_system_agent_detects_kernel_signal() -> None:
    logs = [
        {
            "line_id": "linux_1",
            "dataset": "linux",
            "timestamp_iso": "2015-06-14T15:16:01Z",
            "timestamp_epoch": 1434294961000,
            "level": "error",
            "component": "kernel",
            "message": "kernel panic - not syncing",
        }
    ]
    findings = run_agent(logs)
    assert len(findings) == 1
    assert findings[0]["agent"] == "linux_system_agent"
    assert findings[0]["event_category"] == "system_resource_or_kernel_failure"
