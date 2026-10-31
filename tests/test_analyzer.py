import unittest
from pathlib import Path
from nmap_analyzer import analyze_xml, classify_script

ROOT = Path(__file__).resolve().parents[1]

class AnalyzerTests(unittest.TestCase):
    def test_detects_explicit_vulnerability_evidence(self):
        report = analyze_xml(ROOT / "samples" / "sample_scan.xml")
        self.assertEqual(report["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertIn("CVE-2021-41773", report["findings"][0]["details"])

    def test_closed_port_and_unknown_version_are_not_vulnerabilities(self):
        report = analyze_xml(ROOT / "samples" / "clean_scan.xml")
        self.assertEqual(report["open_ports"], 1)
        self.assertEqual(report["findings"], [])
        self.assertEqual(sum(report["severity_counts"].values()), 0)

    def test_safe_script_output_is_ignored(self):
        self.assertIsNone(classify_script("vulners", "STATE: SAFE. NOT VULNERABLE"))

if __name__ == "__main__":
    unittest.main()
