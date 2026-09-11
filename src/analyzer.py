from collections import Counter
from .models import CSPPolicy, Finding


def analyze(p: CSPPolicy) -> list[Finding]:
    d=p.directives; out=[]
    def add(cid,title,sev,score,evidence,why,fix,check): out.append(Finding(cid,title,sev,score,p.application,evidence,why,fix,check))
    default=d.get("default-src",())
    scripts=d.get("script-src",default)
    objects=d.get("object-src",default)
    base=d.get("base-uri",())
    frames=d.get("frame-ancestors",())
    if not default: add("CSP-001","default-src missing","Medium",55,"directive absent","A default fallback reduces accidental source expansion when resource-specific directives are absent.","Define an application-appropriate restrictive default-src.","Confirm required resources load and unintended sources remain disallowed.")
    if "*" in scripts: add("CSP-002","Wildcard script source","High",82,"script-src contains *","A broad script source materially weakens CSP's script-loading boundary.","Replace broad script sources with explicitly required origins and stronger nonce/hash patterns where appropriate.","Regression-test application scripts and confirm the wildcard is absent.")
    if "'unsafe-inline'" in scripts: add("CSP-003","Inline script allowance present","High",76,"script-src contains 'unsafe-inline'","Broad inline-script allowance reduces CSP protection against injected script content.","Refactor toward nonces or hashes where feasible and validate framework compatibility.","Confirm required inline behavior uses the intended nonce/hash mechanism.")
    if "'unsafe-eval'" in scripts: add("CSP-004","Dynamic code evaluation allowed","High",78,"script-src contains 'unsafe-eval'","Allowing dynamic evaluation weakens the script execution boundary.","Remove the allowance after identifying and refactoring dependencies that require it.","Regression-test affected application features with the allowance removed.")
    if not objects or "'none'" not in objects: add("CSP-005","object-src not explicitly disabled","Medium",48,str(objects) or "directive absent","Applications that do not require plugin/object content can reduce attack surface by explicitly disabling it.","Use object-src 'none' unless a documented requirement exists.","Confirm object/embed content is not required and the directive is enforced.")
    if not base: add("CSP-006","base-uri missing","Medium",50,"directive absent","base-uri constrains document base URL changes that can affect relative resource resolution.","Set base-uri to 'self' or 'none' according to application requirements.","Confirm legitimate base behavior remains functional.")
    if not frames: add("CSP-007","frame-ancestors missing","Medium",52,"directive absent","frame-ancestors provides CSP-level control over which sites may frame the application.","Define permitted framing origins or use 'none' when framing is unnecessary.","Validate approved embedding and confirm unapproved framing is blocked.")
    if p.report_only: add("CSP-008","Policy remains report-only","Low",30,"report_only=true","Report-only mode is valuable during rollout but does not enforce the policy.","Review violation telemetry, resolve legitimate dependencies, then move the tested policy to enforcement under change control.","Confirm the enforced header is present after rollout and monitor regressions.")
    if not p.owner.strip(): add("GOV-001","Policy owner missing","Low",20,"owner empty","CSP tuning requires accountable ownership because policy changes can affect application functionality.","Assign an application/service owner for policy changes and validation.","Confirm ownership is recorded with the policy and change workflow.")
    return sorted(out,key=lambda f:f.score,reverse=True)


def metrics(findings:list[Finding])->dict:
    c=Counter(f.severity for f in findings)
    return {"findings":len(findings),"high_medium":c["High"]+c["Medium"],"highest_score":max((f.score for f in findings),default=0),"severity_counts":dict(c)}
