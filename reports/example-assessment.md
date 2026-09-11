# Example CSP Assessment

> Illustrative assessment based entirely on synthetic policy configuration.

## Executive summary
The synthetic customer portal and documentation site represent stronger baseline policies in the supplied sample. The synthetic legacy portal deliberately contains broad script sources, unsafe-inline, unsafe-eval, missing supporting directives and a report-only rollout state.

## Priority remediation
1. Inventory legitimate script dependencies and remove wildcard script sources.
2. Refactor broad inline-script requirements toward nonce/hash patterns where feasible.
3. Remove dynamic evaluation dependencies where application compatibility permits.
4. Explicitly constrain object-src, base-uri and frame-ancestors.
5. Review report-only telemetry and move the tested policy to enforcement under change control.

## Assurance principle
A CSP improvement should be regression-tested against legitimate application behavior. A stronger policy is valuable only when it is both restrictive and operationally correct.
