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
- Dates and timestamps in hypotheses MUST exactly match ISO timestamps found in
  the provided evidence. Never infer or approximate calendar days from chunk
  indices or summaries. If evidence spans multiple calendar days, label them as
  separate time windows rather than a single thread.
- You are seeing a SUBSET of the total chunk analyses. When only N of M chunks
  are provided, state this uncertainty and its implications for hypothesis
  confidence. Do not assume the unseen chunks confirm or deny your hypotheses.
- Prefer ordered narratives ("A likely preceded B") over bare correlations.
  State confidence, counterevidence, and what log evidence would falsify
  the hypothesis. Frame causal hypotheses as investigative explanations for
  analyst triage. You SHOULD identify causal mechanisms where evidence
  supports them - a mechanism like "failed auth triggered rate-limiting" is
  far more valuable than "A preceded B" - but acknowledge uncertainty rather
  than claiming definitive proof.
- Each hypothesis MUST name its causal mechanism - the reason why X produces
  Y, not just that X preceded Y. If the causal mechanism is unclear, state
  that explicitly and grade the hypothesis `spurious_risk` as "high".
- For each top hypothesis, list plausible benign or alternate explanations
  (routine maintenance, scanner noise, cascading symptom vs root cause).
- For each hypothesis, grade `spurious_risk`: "low" (strong causal chain,
  multi-source evidence, no plausible alternatives), "medium" (plausible but
  with significant counterevidence or missing mechanism), or "high" (temporal
  correlation without a clear causal mechanism). Provide
  `spurious_risk_reasoning`: one sentence explaining why.
- Identify at least one red herring in the overall incident: an event or
  pattern that appears suspicious in isolation but is likely benign or
  coincidental in full context. Explain why an analyst might be misled and
  what the actual explanation is.
- Calibrate confidence (0-1) by the strength of the causal mechanism, not
  just the number of supporting events. Hypotheses with many correlated
  events but no clear mechanism MUST stay low confidence.
- For each hypothesis, list confounding factors: events or conditions that
  could independently explain both the apparent cause and effect."""


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
   g) Build a `causal_chain`: an ordered list of cause-effect-mechanism
      triples that explain the hypothesis end-to-end.
   h) Grade `spurious_risk`: "low", "medium", or "high" with one-sentence
      reasoning.
   i) List `red_herrings`: events or patterns that look suspicious but are
      likely benign or coincidental in context.
   j) Identify `confounding_factors`: conditions that could independently
      explain both the apparent cause and effect.
   k) Assign `confidence_level`: "high", "medium", or "low" to complement
      the numeric confidence.
3) Aggregate category totals.
4) Highlight key timeline moments.
5) Recommend next log queries to validate or refute hypotheses.
6) Identify incident-level `red_herrings`: patterns that appear suspicious in
   isolation but are likely misleading in full context."""
