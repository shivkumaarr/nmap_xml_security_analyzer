# Nmap XML Security Analyzer

A small Python command-line mini project that reads an **existing Nmap XML report** and prints a prioritized security summary.

## Security problem

Raw Nmap XML can be difficult to review quickly. This tool organizes hosts, open ports, detected services, and explicit vulnerability evidence from Nmap NSE script output into a readable report with severity counts.

## Intended users

- Students learning Python and basic network-security reporting
- Junior security analysts reviewing authorized Nmap scan output
- Lab users preparing a quick assessment summary

## Main features

- Parses Nmap XML using Python's built-in XML parser.
- Lists hosts and open TCP/UDP ports with service/version information.
- Extracts explicit CVE and CVSS evidence from NSE script output.
- Groups findings into **CRITICAL, HIGH, MEDIUM, LOW, INFO**.
- Prints a formatted report directly in CMD/Terminal.
- Optionally exports JSON and Markdown reports.
- Avoids treating a closed port, an unknown version, or an ordinary NSE script as proof of a vulnerability.
- Includes sample XML files and automated tests.

## Technology

- Python 3.9+
- `xml.etree.ElementTree`, `argparse`, `json`, `re`, `unittest` (standard library)
- No external Python packages required.

## Installation

1. Install Python 3.9 or newer.
2. Download or extract this project folder.
3. Open CMD/Terminal inside the project folder.
4. (Optional) Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

   Windows CMD:

   ```cmd
   .venv\Scripts\activate
   ```

   macOS/Linux:

   ```bash
   source .venv/bin/activate
   ```

5. Install requirements (there are no third-party dependencies):

   ```bash
   pip install -r requirements.txt
   ```

## Usage

Put your Nmap XML file in the project folder, or provide its full path.

Basic command:

```bash
python nmap_analyzer.py --input samples/sample_scan.xml
```

Windows CMD example:

```cmd
python nmap_analyzer.py -i samples\sample_scan.xml
```

Save JSON and Markdown reports as well:

```bash
python nmap_analyzer.py -i samples/sample_scan.xml --json report.json --markdown report.md
```

The report is also printed in CMD/Terminal. The input XML is read only; it is not modified.

## Sample input and expected output

Sample input: `samples/sample_scan.xml`

The sample contains:
- One host marked up
- Open SSH, HTTP and HTTPS ports
- An explicit `vulners` NSE output line with `CVE-2021-41773` and CVSS 9.8
- A closed MySQL port
- An ordinary HTTP title script

Expected summary (timestamps and formatting may vary):

```text
NMAP XML SECURITY ANALYSIS REPORT
Hosts in XML     : 1 (up: 1)
Open ports       : 3

PRIORITY SUMMARY
CRITICAL  : 1
HIGH      : 0
MEDIUM    : 0
LOW       : 0
INFO      : 0

VULNERABILITY / SECURITY FINDINGS
[1] [CRITICAL] Potential vulnerability reported by vulners
Target      : demo-server.example - 80/tcp (http)
Details     : CVE-2021-41773 | Reported CVSS: 9.8
```

## Testing

Run the included test suite:

```bash
python -m unittest discover -s tests -v
```

Successful tests cover:
1. Explicit CVE/CVSS evidence is detected and prioritized.
2. Closed ports and services with no vulnerability evidence are not reported as vulnerabilities.
3. An explicit safe NSE result is ignored.

## Severity logic

When explicit vulnerability evidence is present:
- **CRITICAL:** CVSS 9.0–10.0
- **HIGH:** CVSS 7.0–8.9
- **MEDIUM:** CVSS 4.0–6.9
- **LOW:** CVSS below 4.0
- If an NSE result explicitly says `VULNERABLE` but contains no score, it is marked HIGH as a review priority, not as a confirmed severity rating.

These are prioritization labels based on the score found in the XML, not an independent CVSS calculation. INFO is reserved in the summary for future informational findings.

## Security considerations

- Use Nmap only on systems and networks you own or are explicitly authorized to assess.
- This project only parses a supplied XML file. It does not initiate network connections, scan targets, or exploit systems.
- Treat XML files as untrusted input. The parser uses Python's XML library and does not execute NSE output.
- Verify CVEs, affected versions, and CVSS scores against authoritative vendor advisories before making remediation decisions.
- Reports may contain internal hostnames, IP addresses, service versions, and security findings. Store and share them appropriately.

## Known limitations

- The analyzer depends on the information already present in the XML file.
- It does not query vulnerability databases or independently confirm whether a service is affected.
- It recognizes explicit CVE/CVSS evidence and vulnerability wording in script output; other NSE output formats may not be recognized.
- CVSS text parsing is intentionally simple and may miss unusual formatting.
- A service banner/version alone is not treated as a vulnerability.
- No findings does not mean the scanned system is secure.
- It does not currently parse host-level NSE vulnerability scripts; the current implementation reads scripts attached to ports.

## Future improvements

- Support additional NSE output formats and host-level scripts.
- Add structured remediation guidance linked to verified vendor advisories.
- Add CSV export and richer filtering.
- Add configurable severity thresholds.

## Project structure

```text
nmap_xml_security_analyzer/
├── nmap_analyzer.py
├── requirements.txt
├── README.md
├── AI_USAGE.md
├── samples/
│   ├── sample_scan.xml
│   └── clean_scan.xml
└── tests/
    └── test_analyzer.py
```
