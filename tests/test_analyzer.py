import unittest
from src.models import CSPPolicy
from src.analyzer import analyze,metrics
from src.reporting import markdown_report

def policy(directives=None,report_only=False,owner="owner"):
    return CSPPolicy("P1","lab",directives or {},report_only,owner)

class Tests(unittest.TestCase):
    def test_missing_default(self): self.assertTrue(any(f.control_id=="CSP-001" for f in analyze(policy())))
    def test_wildcard_script_high(self): self.assertEqual(next(f for f in analyze(policy({"script-src":("*",)})) if f.control_id=="CSP-002").severity,"High")
    def test_unsafe_inline(self): self.assertTrue(any(f.control_id=="CSP-003" for f in analyze(policy({"script-src":("'unsafe-inline'",)}))))
    def test_unsafe_eval(self): self.assertTrue(any(f.control_id=="CSP-004" for f in analyze(policy({"script-src":("'unsafe-eval'",)}))))
    def test_object_none_good(self): self.assertFalse(any(f.control_id=="CSP-005" for f in analyze(policy({"object-src":("'none'",)}))))
    def test_missing_base(self): self.assertTrue(any(f.control_id=="CSP-006" for f in analyze(policy())))
    def test_missing_frame_ancestors(self): self.assertTrue(any(f.control_id=="CSP-007" for f in analyze(policy())))
    def test_report_only(self): self.assertTrue(any(f.control_id=="CSP-008" for f in analyze(policy(report_only=True))))
    def test_metrics(self): self.assertEqual(metrics(analyze(policy()))["findings"],len(analyze(policy())))
    def test_report_safety_statement(self): self.assertIn("No web requests",markdown_report([]))

if __name__=="__main__": unittest.main()
