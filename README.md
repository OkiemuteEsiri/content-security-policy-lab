# Content Security Policy Lab

A defensive Web Application Security engineering project for reviewing Content Security Policy configuration, prioritizing browser-security hardening, and validating remediation using synthetic configuration data.

## Architecture
`synthetic policy JSON -> validated model -> defensive control review -> risk prioritization -> remediation -> revalidation report`

## What the project demonstrates
The implementation reviews core CSP directive coverage and policy quality, including default resource restrictions, script policy strength, object restrictions, base URL controls, framing controls, rollout state, and accountable ownership. It produces evidence-backed findings with deterministic prioritization, remediation guidance, and explicit post-change validation criteria.

## Repository structure
```text
src/        Python models, analyzer, ingestion, reporting and CLI
data/       Synthetic policy configurations
tests/      Ten unit tests
docs/       Architecture and methodology
reports/    Example assessment
.github/    Least-privilege CI workflow
```

## Run locally
Python 3.12+ with no third-party dependencies.
```bash
python -m src.cli data/synthetic_policies.json --output csp-assessment.md
python -m unittest discover -s tests -v
```

## Engineering approach
CSP is treated as defense in depth rather than a substitute for secure application design. Policy changes should be application-specific, tested against legitimate dependencies, introduced under change control, and revalidated after deployment. Observation-only rollout can be useful while teams learn dependencies before enforcement.

The project includes immutable models, normalized directive handling, fail-closed JSON ingestion, duplicate-policy rejection, deterministic 0–100 prioritization, Markdown reporting, synthetic examples, ten tests, and CI with read-only repository permissions.

## Remediation lifecycle
`inventory dependencies -> design policy -> observe/tune -> regression-test -> enforce -> monitor -> capture closure evidence`

## Skills demonstrated
Web application security, browser security controls, secure configuration review, Python security automation, risk communication, remediation assurance, unit testing, and CI/CD.

## Limitations and safety
This is an offline defensive lab. It does not contact websites, perform active testing, discover endpoints, or target production systems. All bundled configurations are synthetic.

## Roadmap
Planned extensions include richer nonce/hash modeling, reporting governance, before/after policy comparison, configurable application profiles, and structured JSON/CSV report export.
