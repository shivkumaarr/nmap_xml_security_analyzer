# AI Usage Disclosure

## 1. Which AI tools did you use?

OpenAI ChatGPT was used as an AI assistant during project planning and drafting.

## 2. How did AI assist you?

AI helped outline the project structure, explain Python XML parsing, suggest a command-line interface, draft documentation, and propose test cases for vulnerability evidence and false-positive handling.

## 3. Which parts were generated or substantially suggested by AI?

The initial versions of `nmap_analyzer.py`, the sample XML files, unit tests, `README.md`, and this disclosure were substantially AI-assisted.

## 4. What mistakes, insecure suggestions or incorrect assumptions did AI make?

AI-generated vulnerability summaries can overstate certainty if they treat an open port or software banner as proof of a vulnerability. A CVE string or CVSS value in scanner output is also not independent confirmation that the installed target is affected. The project was therefore designed to report only explicit vulnerability evidence from the supplied NSE output and to label it as potential evidence requiring verification.

## 5. How did you manually validate the generated code or output?

The project includes automated tests using Python's `unittest`. The tests check explicit CVE/CVSS detection, confirm that a closed port is excluded, confirm that an ordinary service script does not become a vulnerability finding, and check that an explicit safe result is ignored. The sample command can also be run manually to inspect the terminal report.

## 6. What did you change after reviewing the AI-generated work?

The implementation was kept dependency-free, made read-only with respect to the input XML, and limited to parsing existing scan results. It does not scan, exploit, or claim to independently verify vulnerabilities. The README documents the severity thresholds and known limitations.

## 7. Which part of the final project can you confidently explain without AI assistance?

I can explain how the program reads XML elements, checks whether a port is open, extracts service and NSE script information, applies the CVSS-based priority mapping, builds a summary, and prints or exports the report. I can also explain how the unit tests verify detection and false-positive handling.
