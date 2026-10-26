# Threat Intelligence Feed Integrator

A beginner-friendly, defensive Python project that collects indicators of compromise (IOCs) from configured threat-intelligence feeds, normalizes and deduplicates them, and exports a unified JSON and CSV report.

## Features

- Reads indicators from public HTTP(S) feeds or local text/CSV files.
- Supports IP addresses, domains, URLs, and file hashes (MD5, SHA-1, SHA-256).
- Deduplicates indicators while preserving feed/source context.
- Adds collection timestamps and simple indicator-type classification.
- Exports `output/iocs.json` and `output/iocs.csv`.
- Includes offline sample data and unit tests.
- Uses Python's standard library only; no third-party dependencies required.

> This is a learning and triage aid, not a verdict that an indicator is malicious. Validate indicators with trusted sources before blocking or taking action. Use only for authorized defensive security work.
