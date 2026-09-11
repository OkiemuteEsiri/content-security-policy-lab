from .analyzer import metrics

def markdown_report(findings):
    m=metrics(findings)
    lines=["# Content Security Policy Assessment","","> Offline review of synthetic CSP configuration. No web requests or exploit testing were performed.","",f"- Findings: **{m['findings']}**",f"- High/Medium: **{m['high_medium']}**",f"- Highest score: **{m['highest_score']}/100**","","## Findings",""]
    for f in findings:
        lines += [f"### {f.severity} — {f.control_id}: {f.title}","",f"- Application: `{f.application}`",f"- Score: **{f.score}/100**",f"- Evidence: `{f.evidence}`","",f"**Rationale:** {f.rationale}","",f"**Remediation:** {f.remediation}","",f"**Validation:** {f.validation}",""]
    return "\n".join(lines)
