from src.agents.apache_access_agent import run_agent


def test_apache_access_agent_detects_server_error() -> None:
    logs = [
        {
            "line_id": "apache_1",
            "dataset": "apache",
            "timestamp_iso": "2015-06-14T15:16:01Z",
            "timestamp_epoch": 1434294961000,
            "level": "error",
            "component": "apache",
            "message": '10.0.0.2 - - "GET /index HTTP/1.1" 500 123',
        }
    ]
    findings = run_agent(logs)
    assert len(findings) == 1
    assert findings[0]["agent"] == "apache_access_agent"
    assert findings[0]["event_category"] == "apache_server_error_spike"
