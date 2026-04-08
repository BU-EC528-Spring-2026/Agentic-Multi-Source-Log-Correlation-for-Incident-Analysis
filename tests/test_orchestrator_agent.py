from src.agents.orchestrator_agent import run_source_agents


def test_run_source_agents_includes_all_registered_agents() -> None:
    logs = [
        {
            "line_id": "linux_1",
            "dataset": "linux",
            "timestamp_iso": "2015-06-14T15:16:01Z",
            "timestamp_epoch": 1434294961000,
            "level": "error",
            "component": "kernel",
            "message": "kernel panic - not syncing",
            "event_template": "panic",
        },
        {
            "line_id": "apache_1",
            "dataset": "apache",
            "timestamp_iso": "2015-06-14T15:16:02Z",
            "timestamp_epoch": 1434294962000,
            "level": "error",
            "component": "apache",
            "message": '10.0.0.2 - - "GET /index HTTP/1.1" 500 123',
            "event_template": "http_status",
        },
    ]
    findings = run_source_agents(logs)
    agents = {item["agent"] for item in findings}
    assert "linux_system_agent" in agents
    assert "apache_access_agent" in agents
