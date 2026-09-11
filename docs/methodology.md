# CSP Engineering Methodology

## Objective
This lab reviews supplied Content Security Policy configuration as a defensive engineering exercise. It focuses on policy quality, rollout discipline, ownership and remediation validation.

## Pipeline
`synthetic policy JSON -> normalized directives -> control analysis -> deterministic prioritization -> remediation -> revalidation`

## Controls
The current catalog reviews default-src, script-src wildcards, unsafe-inline, unsafe-eval, object-src, base-uri, frame-ancestors, report-only state and accountable ownership.

## Engineering principles
CSP is defense in depth, not a substitute for secure output encoding, framework controls, authorization, dependency security or secure design. A restrictive policy can also break legitimate application behavior if introduced without testing. Report-only mode is therefore treated as a useful rollout state rather than a vulnerability by itself, but long-term enforcement should follow once violations and dependencies are understood.

## Risk model
Scores are deterministic portfolio prioritization values, not CVSS and not exploitability probabilities. Broad script execution allowances receive higher weights because they materially weaken the script boundary. Missing supporting directives receive medium or low weights according to their defensive role.

## Remediation workflow
Inventory legitimate origins and application dependencies; design the least-permissive workable policy; use report-only telemetry during controlled rollout where appropriate; remove unnecessary broad allowances; regression-test critical flows; move to enforcement; monitor violations; capture closure evidence.

## Limitations
This project parses configuration only. It does not request web pages, inject content, test XSS, discover endpoints or determine whether an application is exploitable.
