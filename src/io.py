import json
from pathlib import Path
from .models import CSPPolicy

def load_policies(path:str)->list[CSPPolicy]:
    raw=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw,list): raise ValueError("input must be a JSON array")
    policies=[CSPPolicy.from_dict(x) for x in raw]
    ids=[p.policy_id for p in policies]
    if len(ids)!=len(set(ids)): raise ValueError("duplicate policy_id")
    return policies
