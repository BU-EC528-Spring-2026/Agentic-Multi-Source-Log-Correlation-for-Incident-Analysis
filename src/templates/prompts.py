CATEGORY_TAXONOMY = """
Use only these category labels:
- network
- dns_service_discovery
- authz_security
- process_lifecycle
- power_thermal_kernel
- application
- system_configuration
- hardware
- other
""".strip()


LOG_CATEGORIZATION_SYSTEM = """You are a log analysis assistant.
Classify log events into operational categories and flag suspicious patterns.
Return strictly valid JSON that matches the provided schema.
Prefer concrete, line-based evidence over generic statements."""


LOG_CATEGORIZATION_PROMPT = """Analyze this chunk of system logs.

Chunk metadata:
- chunk_id: {chunk_id}
- line_range: {line_start}-{line_end}

Logs:
{log_block}

Category taxonomy:
{category_taxonomy}

Task:
1) Group events by category and severity.
2) Identify high-signal suspicious events with specific line numbers.
3) Write a concise chunk summary.

Rules:
- Use only evidence present in these lines.
- Keep `category_counts` keyed by the taxonomy labels only.
- Keep `evidence` concise and concrete."""


CORRELATION_SYSTEM = """You are an incident correlation assistant.
Your job is to synthesize chunk-level and source-scoped analyses into a
single coherent incident view with testable, falsifiable hypotheses.
Return strictly valid JSON that matches the provided schema.

Ground rules:
- Every claim must cite specific evidence from the provided analyses.
- When a hypothesis spans multiple subsystems (e.g. auth + infra), it MUST
  cite evidence from at least two distinct sources / chunk groups.
- Prefer ordered narratives ("A likely preceded B") over bare correlations.
  State confidence, counterevidence, and what log evidence would falsify
  the hypothesis. Do NOT claim causal discovery; frame as investigative
  hypotheses for analyst triage.
- For each top hypothesis, list plausible benign or alternate explanations
  (routine maintenance, scanner noise, cascading symptom vs root cause)."""


CORRELATION_PROMPT = """Correlate these analyses into a baseline incident view.

Chunk analyses (general log windows):
{chunk_analysis_json}
{source_scoped_section}{source_agent_findings_section}
Category taxonomy:
{category_taxonomy}

Task:
1) Identify repeated or temporally linked patterns across ALL provided
   analyses (chunks AND source-scoped).
2) Build structured hypotheses. For each hypothesis:
   a) Provide an ordered narrative ("A likely preceded B because …").
   b) List which sources contributed evidence (e.g. "openssh", "openstack",
      "chunk 3"). Cross-subsystem hypotheses MUST cite ≥2 sources.
   c) Assign a confidence score (0-1) grounded only in provided evidence.
   d) Note counterevidence or gaps that weaken the hypothesis.
   e) State what log evidence would falsify it.
   f) List benign / alternate explanations (routine maintenance, scanner
      noise, symptom-not-cause, config drift, etc.).
3) Aggregate category totals.
4) Highlight key timeline moments.
5) Recommend next log queries to validate or refute hypotheses."""
