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


LOG_CATEGORIZATION_PROMPT = """Analyze this chunk of macOS logs.

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
Infer relationships across chunk analyses and build testable hypotheses.
Return strictly valid JSON that matches the provided schema."""


CORRELATION_PROMPT = """Correlate these chunk-level analyses into a baseline incident view.

Chunk analyses:
{chunk_analysis_json}

Category taxonomy:
{category_taxonomy}

Task:
1) Identify repeated or temporally linked patterns.
2) Produce candidate correlation hypotheses.
3) Provide confidence scores based only on provided evidence.
4) Recommend next log queries to validate hypotheses."""
