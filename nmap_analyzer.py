#!/usr/bin/env python3
"""
Nmap XML Security Analyzer
Parses an existing Nmap XML report and creates a prioritized, evidence-based summary.
This tool does not scan networks or exploit vulnerabilities.
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

def clean(value):
    return re.sub(r"\s+", " ", value or "").strip()

def classify_script(script_id, output):
    """Classify only explicit Nmap NSE vulnerability evidence; do not infer CVEs."""
    text = clean(output)
    upper = text.upper()
    if not text:
        return None

    # An explicit safe/not-vulnerable result takes precedence over other words.
    if "NOT VULNERABLE" in upper or "STATE: SAFE" in upper:
        return None

    # Nmap's vulners script commonly prints CVE identifiers and CVSS scores.
    scores = [float(x) for x in re.findall(r"(?:CVSS|SCORE)\s*[:=]?\s*(\d{1,2}(?:\.\d+)?)", upper)]
    cves = sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", upper)))
    if "VULNERABLE" in upper or cves or "VULNERABILITY" in upper:
        score = max(scores) if scores else None
        if score is not None:
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        else:
            severity = "HIGH" if "VULNERABLE" in upper else "MEDIUM"
        details = []
        if cves:
            details.append("CVEs: " + ", ".join(cves))
        if score is not None:
            details.append(f"Reported CVSS: {score:.1f}")
        details.append(f"NSE script: {script_id}")
        details.append("Evidence: " + text[:500])
        return {
            "severity": severity,
            "title": f"Potential vulnerability reported by {script_id}",
            "details": " | ".join(details),
            "evidence_based": True,
        }

    return None

def analyze_xml(xml_path):
    path = Path(xml_path)
    if not path.is_file():
        raise FileNotFoundError(f"Input XML file not found: {path}")
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML: {exc}") from exc

    hosts = []
    findings = []
    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"
        addresses = []
        for addr in host.findall("address"):
            val = addr.get("addr")
            if val:
                addresses.append(val)
        hostname_el = host.find("./hostnames/hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""
        host_label = hostname or (", ".join(addresses) if addresses else "unknown host")

        host_record = {
            "host": host_label,
            "status": status,
            "addresses": addresses,
            "open_ports": [],
        }

        # Only open ports are included in the exposed-service inventory.
        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            if state != "open":
                continue

            protocol = port.get("protocol", "unknown")
            port_id = port.get("portid", "unknown")
            service_el = port.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            extra = service_el.get("extrainfo", "") if service_el is not None else ""
            service_desc = clean(" ".join(x for x in [product, version, extra] if x)) or "version not identified"

            port_record = {
                "port": port_id,
                "protocol": protocol,
                "service": service_name,
                "version": service_desc,
            }
            host_record["open_ports"].append(port_record)

            # NSE vulnerability script evidence is reported; ordinary scripts are not
            # automatically treated as vulnerabilities.
            for script in port.findall("script"):
                script_id = script.get("id", "unknown")
                result = classify_script(script_id, script.get("output", ""))
                if result:
                    findings.append({
                        "host": host_label,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        **result,
                        "recommendation": "Verify the affected software/version with the vendor advisory, patch if applicable, and rescan.",
                    })

        hosts.append(host_record)

    counts = {level: sum(1 for f in findings if f["severity"] == level) for level in SEVERITIES}
    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_file": path.name,
        "hosts_scanned": len(hosts),
        "hosts_up": sum(1 for h in hosts if h["status"] == "up"),
        "open_ports": sum(len(h["open_ports"]) for h in hosts),
        "severity_counts": counts,
        "hosts": hosts,
        "findings": findings,
        "limitations": [
            "This report summarizes evidence present in the supplied XML; it does not perform a scan.",
            "A service/version or open port alone is not proof of a vulnerability.",
            "NSE output and CVSS values may be incomplete, stale, or require manual verification.",
            "No finding does not mean the host is secure.",
        ],
    }

def render_report(data):
    lines = []
    lines += ["", "=" * 68, "             NMAP XML SECURITY ANALYSIS REPORT", "=" * 68]
    lines.append(f" Source XML       : {data['source_file']}")
    lines.append(f" Generated        : {data['generated_at']}")
    lines.append(f" Hosts in XML     : {data['hosts_scanned']} (up: {data['hosts_up']})")
    lines.append(f" Open ports       : {data['open_ports']}")
    lines.append("-" * 68)
    lines.append(" PRIORITY SUMMARY")
    for level in SEVERITIES:
        lines.append(f" {level:<10}: {data['severity_counts'][level]}")
    lines.append("-" * 68)
    lines.append(" OPEN SERVICE INVENTORY")
    for host in data["hosts"]:
        lines.append(f"\n Host: {host['host']} [{host['status']}]")
        if not host["open_ports"]:
            lines.append("   No open ports recorded.")
        for p in host["open_ports"]:
            lines.append(f"   {p['port']}/{p['protocol']}  {p['service']}  ({p['version']})")
    lines.append("\n" + "-" * 68)
    lines.append(" VULNERABILITY / SECURITY FINDINGS")
    if not data["findings"]:
        lines.append(" No explicit vulnerability evidence was found in the supplied XML.")
        lines.append(" Note: this is not proof that the hosts are vulnerability-free.")
    for i, f in enumerate(data["findings"], 1):
        lines.append(f"\n [{i}] [{f['severity']}] {f['title']}")
        lines.append(f"     Target      : {f['host']} - {f['port']}/{f['protocol']} ({f['service']})")
        lines.append(f"     Details     : {f['details']}")
        lines.append(f"     Action      : {f['recommendation']}")
    lines.append("\n" + "-" * 68)
    lines.append(" SCOPE & LIMITATIONS")
    for item in data["limitations"]:
        lines.append(f" - {item}")
    lines.append("=" * 68)
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze an existing Nmap XML file and print a prioritized security summary."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to Nmap XML file")
    parser.add_argument("--json", dest="json_out", help="Optional path to save JSON report")
    parser.add_argument("--markdown", dest="md_out", help="Optional path to save Markdown report")
    args = parser.parse_args()

    try:
        report = analyze_xml(args.input)
        output = render_report(report)
        print(output)
        if args.json_out:
            Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"\n[+] JSON report saved: {args.json_out}")
        if args.md_out:
            Path(args.md_out).write_text("# Nmap XML Security Analysis\n\n```text\n" + output + "\n```\n", encoding="utf-8")
            print(f"[+] Markdown report saved: {args.md_out}")
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
