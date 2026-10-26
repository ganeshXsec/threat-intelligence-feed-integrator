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

## Requirements

- Python 3.10 or newer
- Internet access only when collecting remote feeds

## Quick start (offline demo)

From this folder, run:

```bash
python threat_intel_integrator.py --input data/sample_iocs.txt
```

The program writes:
- `output/iocs.json`
- `output/iocs.csv`

The sample file contains documentation/example indicators and is intended for testing, not for blocking.

## Collect from configured feeds

Edit `config.json` and add/remove feed URLs. Then run:

```bash
python threat_intel_integrator.py
```

Example configuration:

```json
{
  "feeds": [
    {
      "name": "OpenPhish Community Feed",
      "url": "https://openphish.com/feed.txt",
      "format": "text"
    },
    {
      "name": "URLhaus Recent URLs",
      "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
      "format": "auto"
    }
  ],
  "timeout_seconds": 15,
  "max_bytes_per_feed": 5000000
}
```

Feed formats:
- `text`: one indicator per line; lines beginning with `#` or `;` are ignored.
- `csv`: indicators are extracted from cells in each row.
- `auto`: handles common comment/header lines and extracts indicator-like values from lines.

Feeds can change format, rate-limit requests, or become unavailable. The tool reports per-feed errors and continues with other feeds. Always check each provider's current terms and recommended access method before using a feed.

## Use your own local file

```bash
python threat_intel_integrator.py --input path/to/indicators.txt --output-dir output
```

For a CSV file:

```bash
python threat_intel_integrator.py --input path/to/indicators.csv --input-format csv
```

## Output fields

| Field | Description |
|---|---|
| `indicator` | Normalized indicator value |
| `type` | `ip`, `domain`, `url`, or `hash` |
| `sources` | Feed names where the indicator appeared |
| `first_seen_by_tool` | UTC time when this run collected it |
| `source_count` | Number of distinct sources containing it |

`first_seen_by_tool` is the collection time in this tool, not the original first-seen time reported by a feed.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Suggested GitHub repository description

`Python tool to aggregate, normalize, deduplicate, and export IOCs from threat-intelligence feeds for defensive SOC analysis.`

## Suggested GitHub topics

`cybersecurity`, `threat-intelligence`, `soc`, `python`, `ioc`, `blue-team`, `security-automation`

## Limitations

- Feed formats are not guaranteed to remain stable.
- Does not automatically block, quarantine, scan, or contact indicators.
- Does not assign a maliciousness score; source presence is context, not proof.
- URL and domain validation is intentionally lightweight and is not a substitute for a full standards-compliant parser.
