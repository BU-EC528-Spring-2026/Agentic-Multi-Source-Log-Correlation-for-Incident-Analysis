# Log pipeline backend

This EC528 project explores how multi-agent LLM systems can help with incident analysis across heterogeneous logs. Instead of treating logs as isolated streams, the project aims to connect signals from sources such as authentication, networking, host or kernel activity, and application services to generate evidence-backed root cause hypotheses.

## Why This Project

Real incidents often produce symptoms in many places at once, while the actual cause starts upstream in only one part of the system. Traditional log analysis can surface related events, but it does not always explain which events are causal and which are only correlated. Our project focuses on building an agentic workflow that retrieves relevant evidence, analyzes each source in context, and iteratively refines likely explanations.

## Core Idea

At a high level, the system is designed around four steps:

1. Ingest and normalize logs from multiple sources into a structured format.
2. Retrieve the most relevant evidence using a hybrid of keyword filtering and semantic search.
3. Let source-specific agents analyze retrieved evidence and produce structured findings.
4. Use a correlation agent to assemble those findings into ranked root cause hypotheses with supporting evidence and confidence estimates.

An optional critic or validator agent can challenge weak hypotheses and request additional retrieval before the final report is produced.

## What Matters Most

The main ideas pulled from the project spec are:

- Multi-source reasoning is the central problem, not single-log summarization.
- Retrieval quality matters, so the project uses both deterministic filtering and semantic similarity.
- Agents should produce structured outputs, not just free-form explanations.
- Final conclusions should be evidence-backed, ranked, and traceable to specific log lines.
- The system should support iteration: retrieve more evidence, update the hypothesis, and stop when confidence stabilizes.

## Expected Outputs

The end goal is a structured incident report that includes:

- A concise incident summary
- Ranked root cause hypotheses
- Confidence scores
- Evidence references
- Timeline highlights
- Suggested follow-up queries

## Planned Stack

- Python for the main implementation
- Ollama locally in the initial phase, with OpenRouter as a planned upgrade path
- Hybrid retrieval using regex or keyword search plus embeddings
- A lightweight local storage layer such as JSON files or SQLite
- Docker for reproducible deployment

## Repository Status

This repository is currently in an early stage and does not yet contain the full implementation described above. The README reflects the distilled project direction and intended system design from the EC528 spec.

## Demo Presentations

- [Demo 1](https://docs.google.com/presentation/d/1GPAEH4Cf7paiDZ0z6zxIpxNn0OVbhj9mYld-0ZLKsgY/edit?slide=id.p#slide=id.p)
- [Demo 2](https://docs.google.com/presentation/d/1utnqEQaKfqSOjF4wya7j3ddD0Xs1_japXFvNtP1JG6o/edit?usp=sharing)
