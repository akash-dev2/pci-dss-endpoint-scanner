# Results

Artifact version: v1.0 (August 2025)

The JSONL files in this directory are public-release sanitized copies of the raw
scanner output:

- host identifiers are normalized to `reference-host`
- absolute local paths are converted to project-relative paths
- machine execution timestamps are omitted

The detection records, counts, and published metrics are unchanged.
`results/reproduction_receipt.txt` contains SHA-256 hashes for the sanitized files.

To reproduce the metrics from scratch, run the command sequence in the top-level
README. The scanner will emit absolute paths on your machine, which
`evaluation/evaluate_scanner.py` expects when matching against
`corpus/manifest.json`.
