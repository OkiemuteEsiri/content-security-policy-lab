from dataclasses import dataclass

@dataclass(frozen=True)
class CSPPolicy:
    policy_id: str
    application: str
    directives: dict[str, tuple[str, ...]]
    report_only: bool
    owner: str

    @classmethod
    def from_dict(cls, row: dict) -> "CSPPolicy":
        for key in ("policy_id", "application", "directives", "report_only", "owner"):
            if key not in row: raise ValueError(f"missing required field: {key}")
        if not isinstance(row["directives"], dict): raise ValueError("directives must be an object")
        normalized = {str(k).lower(): tuple(str(v) for v in values) for k, values in row["directives"].items()}
        return cls(str(row["policy_id"]), str(row["application"]), normalized, bool(row["report_only"]), str(row["owner"]))

@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    score: int
    application: str
    evidence: str
    rationale: str
    remediation: str
    validation: str
