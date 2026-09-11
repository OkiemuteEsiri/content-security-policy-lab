import argparse
from pathlib import Path
from .analyzer import analyze
from .io import load_policies
from .reporting import markdown_report

def main():
    p=argparse.ArgumentParser(description="Review supplied CSP policy configuration offline")
    p.add_argument("input"); p.add_argument("--output",default="csp-assessment.md")
    a=p.parse_args(); findings=[f for policy in load_policies(a.input) for f in analyze(policy)]
    Path(a.output).write_text(markdown_report(findings),encoding="utf-8")
    print(f"Wrote {a.output} with {len(findings)} findings")

if __name__=="__main__": main()
