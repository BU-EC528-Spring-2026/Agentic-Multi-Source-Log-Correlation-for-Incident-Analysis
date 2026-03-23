# Agentic Multi-Source Log Correlation for Incident Analysis

This repository contains our EC528 project on building an agentic, retrieval-augmented incident reasoning system for multi-source log analysis. The goal is to move beyond simple log correlation and produce ranked, evidence-backed root cause hypotheses from heterogeneous system logs.

## Project Overview

Modern incidents rarely come from a single component. Failures often span networking, authentication, host processes, kernel activity, infrastructure signals, and application services. In many cases, downstream errors are symptoms of one upstream issue. This project focuses on designing a system that can retrieve relevant evidence across log sources, analyze each source with specialized agents, correlate those findings, and iteratively refine likely root-cause explanations.

The emphasis is on causal hypothesis generation and refinement, not automated remediation or guaranteed root-cause certainty.

## Project Goals

- Ingest and normalize heterogeneous log sources.
- Implement hybrid retrieval using keyword or regex filtering plus semantic search.
- Use source-specific agents to extract structured anomalies and suspicious events.
- Correlate cross-source signals into candidate causal chains.
- Generate ranked root-cause hypotheses with confidence scores.
- Support an agentic retrieve -> reason -> evaluate loop for iterative refinement.
- Ensure explainability through explicit evidence citation.

## Functional Requirements

### 1. Log Ingestion

The system should support at least 3-4 distinct log sources, such as:

- Network logs
- Authentication logs
- Kernel or host logs
- Application or database logs

Supported data may be synthetic or sampled from real-world datasets such as OpenStack or LogHub. The ingestion layer is expected to:

- Parse raw logs with deterministic parsing methods such as regex.
- Normalize timestamps and structure records into JSON.
- Assign unique line identifiers for traceability.

### 2. Retrieval Layer

The retrieval layer should combine multiple strategies:

- Keyword or regex retrieval
- Time-window filtering
- Process-based filtering
- Embedding-based semantic retrieval
- Hybrid retrieval that narrows by keyword or time and then re-ranks semantically

Returned evidence should remain structured and traceable, including:

- Log identifier
- Timestamp
- Source category
- Raw message

### 3. Source-Specific Analysis Agents

Each source agent should operate only on retrieved evidence relevant to its source and output structured results instead of free-form text alone. Expected extracted fields include:

- Event category
- Severity
- Timestamp
- Evidence identifiers

Example source agents include host or kernel, authentication, network, database, and infrastructure agents.

### 4. Correlation and Root Cause Agent

The correlation layer should consume the structured outputs from source agents and:

- Identify temporal and categorical relationships
- Construct candidate causal chains
- Propose ranked root-cause hypotheses
- Assign confidence scores
- Explicitly cite supporting evidence

The system should distinguish between correlated events and hypothesized upstream causes.

### 5. Critic or Validation Agent

In the advanced phase, a critic agent should:

- Challenge top-ranked hypotheses
- Surface alternative explanations
- Reduce overconfidence
- Suggest additional retrieval queries

### 6. Agentic Iterative Loop

The overall workflow should support iterative reasoning:

1. Generate a hypothesis.
2. Evaluate confidence.
3. Identify missing evidence.
4. Retrieve targeted logs.
5. Re-run correlation.
6. Stop when confidence stabilizes or an iteration limit is reached.

### 7. Output Requirements

The system should produce a structured incident report containing:

- Global summary
- Ranked hypotheses
- Confidence scores
- Explicit evidence references
- Timeline highlights
- Recommended follow-up queries

Expected output format: JSON plus a human-readable summary.

## Proposed Technology Stack

- Language: Python
- LLM access: local inference via Ollama in the initial phase, with a planned switch to OpenRouter
- Retrieval: keyword or regex filtering plus embedding-based semantic search
- Vector backend: FAISS, SPTAG, or an equivalent ANN solution
- Storage: local files or a lightweight database such as SQLite
- Deployment: Docker container
- Version control: Git and GitHub

## High-Level Architecture

```text
Log Ingestion
    ->
Parsing and Structuring
    ->
Hybrid Retrieval (Keyword + Semantic)
    ->
Source-Specific Agents
    ->
Correlation / Root Cause Analysis Agent
    ->
Critic / Validation Agent
    ->
Final Incident Report
```

## Risks and Mitigations

- LLM hallucination: enforce strict schemas and require evidence citation.
- Correlation mistaken for causation: build and rank explicit causal chains.
- Retrieval noise: combine keyword filtering with semantic retrieval.
- Overconfidence in hypotheses: use critic-agent review and confidence thresholds.

## Current Repository Status

This repository currently contains the project README and supporting local artifacts only. The implementation work described above is the project target defined by the EC528 specification and should be treated as planned system scope unless corresponding code and documentation are added here.

## Demo Presentations

- [Demo 1](https://docs.google.com/presentation/d/1GPAEH4Cf7paiDZ0z6zxIpxNn0OVbhj9mYld-0ZLKsgY/edit?slide=id.p#slide=id.p)
- [Demo 2](https://docs.google.com/presentation/d/1utnqEQaKfqSOjF4wya7j3ddD0Xs1_japXFvNtP1JG6o/edit?usp=sharing) 