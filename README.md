# Correlation Agent

This component implements the **Correlation Agent** for the project *Agentic Multi-Source Log Correlation for Incident Analysis*.

The purpose of the correlation agent is to **identify and group related log events across multiple systems** (application, infrastructure, thermal, etc.) so that higher-level agents can perform **incident analysis and root cause reasoning**.

This module takes structured log events as input and outputs **correlated event groups**.

---

# Functionality

The correlation agent groups logs using three main signals:

## 1. Time Window Correlation

Events must occur within a configurable time window to be considered related.

Default window: 30 seconds

Example:
- 12:00:01 App error
- 12:00:05 Pod restart

These events may belong to the same incident.

---

## 2. Entity-Based Correlation

Logs are correlated if they share common identifiers such as:

- trace_id
- request_id
- host
- service
- pod
- container
- ip

Example:

- App Log, trace_id = abc123, message = request failed
- Infra Log, trace_id = abc123, message = container restarted

These will be grouped into the same correlation group.

---

## 3. Message Similarity (Fallback)

If entity matching fails, the agent compares **log message similarity**.

Example:

- TLS handshake failed for upstream 10.0.0.12
- TLS handshake failure to upstream 10.0.0.99

If similarity exceeds the threshold, the logs will still be correlated.

---

# File Structure

correlation_agent.py # core correlation logic
test_correlation_agent.py # unit tests for the correlation agent
requirements.txt
.gitignore

---

# Log Event Format

The correlation agent expects logs in a **structured format**.

Example:

```python
{
  "event_id": "evt_1",
  "timestamp": "2026-03-04T12:00:00Z",
  "source": "app",
  "level": "ERROR",
  "message": "request failed",
  "trace_id": "abc123",
  "service": "checkout"
}
```

# Running Tests

```bash
# Install dependencies
pip install -r requirements.txt
# Run test
pytest -q
# Expected output 
4 passed
```

The tests verify that the agent correctly:
- correlates events with shared identifiers
- avoids correlating events outside the time window
- correlates events based on message similarity
- optionally enforces multi-source correlation 
