# PCI DSS Endpoint Scanner — Reproducibility Artifact

Version 1.0 (research paper v1.0, August 2025)

Repository: https://github.com/akash-dev2/pci-dss-endpoint-scanner

## Paper
- [`paper/Akash_Dev_Research_Paper.docx`](paper/Akash_Dev_Research_Paper.docx) — editable Word version (v1.0, August 2025)
- [`paper/manuscript.md`](paper/manuscript.md) — Markdown source

Standard-library-only Python scanner for PCI DSS v4.0.1 PAN/SAD detection,
designed for Active Directory Group Policy deployment, evaluated against a
deterministic synthetic corpus.

## Layout
- `scanner/lightweight_pci_scanner.py` — Conditions P (IIN validation) and A (Luhn only)
- `scanner/iin_rules-v1.0.json` — versioned issuer/length rule set
- `corpus/generate_corpus.py` — deterministic corpus + `manifest.json` (seed 42, 5,000 files)
- `evaluation/evaluate_scanner.py` — file-level metrics, Wilson CIs, McNemar tests, FP classification
- `evaluation/resource_monitor.py` — throughput/CPU/peak-memory protocol + simulated GPO latency model
- `evaluation/make_tables.py` — manuscript fill-points from measured outputs
- `evaluation/cross_check_scanner.py` — Condition B independent cross-check implementation
- `configs/` — per-condition scanner configurations
- `results/` — metrics.json, overhead.json, fp_classification.csv, condition outputs, environment.json
- `deployment/` — GPO bootstrap script and configuration notes
- `paper/manuscript.md` — filled manuscript; `paper/manuscript_fillpoints.json` — value provenance

## Reproduce
```
python corpus/generate_corpus.py --out corpus --files 5000 --seed 42
python scanner/lightweight_pci_scanner.py corpus --config configs/condition_P.json --out results/condition_P/scan_results.jsonl
python scanner/lightweight_pci_scanner.py corpus --config configs/condition_A.json --out results/condition_A/scan_results.jsonl
python evaluation/cross_check_scanner.py corpus --out results/condition_B/scan_results.jsonl
python evaluation/evaluate_scanner.py --manifest corpus/manifest.json --conditions results/condition_P results/condition_A results/condition_B --out results/metrics.json
python evaluation/resource_monitor.py --corpus corpus --out results/overhead.json
python evaluation/make_tables.py --metrics results/metrics.json --overhead results/overhead.json --false-positives results/fp_classification.csv --out paper/manuscript_fillpoints.json
```

## Provenance notes (important)
- `results/metrics.json`, `results/fp_classification.csv`, `results/environment.json`
  values are **measured** from the runs above on this machine.
- `results/overhead.json` scan columns (throughput, CPU, peak RSS, result size,
  failure rate) are **measured** from 1 warm-up + 30 repetitions per condition.
- The `deployment_latency` block in `results/overhead.json` is a **simulated
  demo model** of the Appendix C protocol (10 endpoints × 20 cycles). No live
  Active Directory forest was available in the authoring environment. Re-run
  the Appendix C protocol before relying on those numbers for submission.
- Artifact version: **v1.0 (August 2025)**. The manuscript text was completed
  August 2025. The public artifact was assembled and verified on Python 3.13.x
  (released May 2026); detection metrics are unchanged by the verification runtime.
- Raw JSONL outputs are public-release sanitized: host identifiers normalized to
  `reference-host`, paths converted to project-relative, machine timestamps omitted.
  Detection records, counts, and published metrics are unchanged.

## Coverage caveats
Per-file read capped at 5 MiB; text-oriented detection; no in-memory,
encoded, or database-resident SAD; unmatched Luhn-valid candidates recorded
as `unmatched_luhn_valid` and excluded from PAN positives.
