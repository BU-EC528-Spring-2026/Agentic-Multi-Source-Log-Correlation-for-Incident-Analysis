# Synthetic Dataset Evaluation Rubric

Use this sheet to evaluate full-pipeline runs on the synthetic datasets under `data/synthetic_logs/`.

## How To Score

Score each seeded scenario on a `0-3` scale:

- `0` = missed entirely
- `1` = partially detected, but wrong actor, asset, timeline, or correlation
- `2` = correctly detected with mostly correct context
- `3` = correctly detected, well-correlated, and clearly explained

Score report quality on a `0-2` scale:

- `0` = poor
- `1` = mixed / partially correct
- `2` = strong

Suggested totals:

- `scenario_score` = sum of seeded scenario scores
- `quality_score` = sum of quality dimension scores
- `total_score` = `scenario_score + quality_score`

## Quality Dimensions

Score these for every run:

| Dimension | What to look for |
| --- | --- |
| factual_correctness | Are the report claims supported by the logs? |
| coverage | Did the report cover the main seeded incidents? |
| false_positive_control | Did it avoid inventing incidents or overclaiming severity? |
| actionability | Are the follow-up recommendations specific and useful? |

## GPT5.4 Synthetic Dataset

Dataset: `data/synthetic_logs/GPT5.4_synthetic_logs.jsonl`

### Seeded Scenarios

| Scenario ID | Ground Truth | Expected Good Detection |
| --- | --- | --- |
| A1 | Recon / suspicious access sequence from `173.234.31.186` across Apache, OpenSSH, and Linux | Recognize cross-source probing or auth-related suspicious behavior, not just a single invalid user line |
| A2 | Password SSH login for `deploy` from `10.11.10.21` | Flag risky password auth on a service / privileged account |
| A3 | Deployment workflow issue around `00:03` | Correlate `deploy-check`, Apache `/api/deploy` proxy error, and `sudo` escalation to root by `deploy` |
| A4 | Infra degradation around `00:07` | Correlate `eth0` link down/up, Apache backend error, Nova `500/503`, and possibly TLS `unknown_ca` |
| A5 | Password SSH login for `analyst` from external `198.51.100.21` | Flag suspicious external password auth |
| A6 | OpenStack instance soft delete | Mention instance deletion as a notable operational or security-relevant event |

### Scoring Table

| Scenario ID | Score (0-3) | Notes |
| --- | --- | --- |
| A1 |  |  |
| A2 |  |  |
| A3 |  |  |
| A4 |  |  |
| A5 |  |  |
| A6 |  |  |

### Quality Scoring

| Dimension | Score (0-2) | Notes |
| --- | --- | --- |
| factual_correctness |  |  |
| coverage |  |  |
| false_positive_control |  |  |
| actionability |  |  |

## Sonnet4.6 Synthetic Dataset

Dataset: `data/synthetic_logs/Sonnet4.6_synthetic_logs.jsonl`

### Seeded Correlated Scenarios

| Scenario ID | Correlation ID | Ground Truth | Expected Good Detection |
| --- | --- | --- | --- |
| B1 | `corr-A` | Auth failure + unknown user + invalid user + Apache forbidden admin path from `218.188.2.4` | Recognize a correlated recon / auth-probing sequence from one source |
| B2 | `corr-B` | OpenStack instance spawn followed by successful `ubuntu` login / session open from `10.11.10.55` | Recognize a spawn-plus-access pattern and preserve the timeline |
| B3 | `corr-C` | Instance termination + user logout / disconnect + Apache `mod_jk` error | Detect the grouped shutdown / error sequence without inventing causality not in evidence |
| B4 | `corr-D` | OpenStack claim attempt + claim success | Keep this low severity or benign; it is a positive control for over-alerting |
| B5 | `corr-E` | Kerberos failure + failed root SSH from `192.168.0.31` | Recognize a correlated authentication-failure sequence |

### Background / Noise Expectations

Events with `correlation_id = null` should generally remain background unless the pipeline has strong evidence to elevate them. Use them to judge false positives and over-correlation.

### Scoring Table

| Scenario ID | Score (0-3) | Notes |
| --- | --- | --- |
| B1 |  |  |
| B2 |  |  |
| B3 |  |  |
| B4 |  |  |
| B5 |  |  |

### Quality Scoring

| Dimension | Score (0-2) | Notes |
| --- | --- | --- |
| factual_correctness |  |  |
| coverage |  |  |
| false_positive_control |  |  |
| actionability |  |  |

## Interpretation Guide

You can summarize each run with these derived metrics:

- `incident_recall`: seeded positive scenarios detected / total seeded positive scenarios
- `incident_precision`: correctly detected seeded scenarios / total reported incident scenarios
- `correlation_accuracy`: number of correctly grouped seeded scenarios / total seeded scenarios
- `benign_suppression`: whether benign scenarios such as `corr-D` stayed low severity

## Notes Template

Use this short template when reviewing a run:

```text
Run:
Dataset:
Report:
Model:

Strongest correct findings:
- ...

Missed scenarios:
- ...

False positives / overclaims:
- ...

Top follow-up fixes for the pipeline:
- ...
```
