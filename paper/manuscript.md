# A Comparative Evaluation of a Lightweight Endpoint Scanner Designed for Active Directory Group Policy Deployment for PCI DSS Cardholder Data Detection

**Author:** Akash Dev  
**Institution:** Daffodil International University, Dhaka, Bangladesh  
**Degree:** B.Sc. in Software Engineering (Major: Cyber Security)  
**Document type:** Independent academic research paper  
**Version:** v1.0 (August 2025)  
**Artifact note:** The manuscript text was completed August 2025. The public artifact was assembled and the reproduction receipt was generated on Python 3.14.5 (released May 2026); detection metrics are unchanged by the verification runtime.  

## Abstract

PCI DSS v4.0.1 Requirement 3.3.1 prohibits retention of sensitive authentication data (SAD) after authorization, including in logs, caches, and temporary files, while Requirement 12.5.2 requires documented confirmation of PCI DSS scope at least annually and upon significant change. Lightweight endpoint scanners are marketed as a low-friction mechanism for generating location evidence for these obligations, but independent, reproducible evaluations remain limited. This paper presents a lightweight, standard-library-only cardholder-data scanner designed for Active Directory Group Policy deployment and evaluates it against a scripted Luhn-only baseline and an independently implemented cross-check scanner. Using a deterministic synthetic corpus of 5,000 files—comprising 588 PAN-positive files, 4,100 PAN-negative and non-SAD files, and 312 Track 1/Track 2 SAD-only files—we measure file-level true-positive rate, false-positive rate, precision, and F1 score, with Wilson 95% confidence intervals. We report scan throughput, CPU time, and peak resident memory over repeated executions, and bootstrap deployment latency under a deterministic simulated refresh-schedule model that implements the study's deployment-latency protocol (10 endpoints × 20 cycles; modelled, not measured on a live estate). The proposed scanner achieved a PAN true-positive rate of 96.94% (95% CI [95.21, 98.06]) and a false-positive rate of 0.54% (95% CI [0.35, 0.81]), compared with 100.00% TPR and 2.68% FPR for the Luhn-only baseline. Issuer identification number and length validation reduced false positives by 80.0% at a recall cost of 3.06 percentage points. SAD recall is measured only within the detector's implemented plaintext Track 1/Track 2 and CVV-context envelope; it is not an estimate of real-world SAD recall. Median scan throughput was 3.08 seconds per gigabyte, with peak resident memory of 17.96 MB. We conclude that issuer-based allowlist validation delivers a material false-positive reduction over Luhn-only detection at a modest recall cost, while retaining within-envelope SAD-like coverage and an operational footprint compatible with Group Policy deployment. The scanner, Group Policy deployment scripts, corpus generator, evaluation harness, raw outputs, and analysis scripts are released as a reproducibility artifact.

**Keywords:** PCI DSS; endpoint scanning; Active Directory; Group Policy; cardholder data; sensitive authentication data; primary account number; Luhn algorithm; issuer identification number; security-tool evaluation

## 1. Introduction

Payment card data is a tightly regulated class of personal information, and the Payment Card Industry Data Security Standard (PCI DSS) operationalises much of that regulation. PCI DSS v4.0.1 [1], a limited revision of v4.0 [2] published in June 2024, retains two obligations that bear directly on endpoint data discovery. Requirement 3.3.1 states that sensitive authentication data—full magnetic-stripe data, card verification codes, and PINs—must not be retained after authorization, even in encrypted form, and explicitly includes logs, caches, and temporary files within its scope. Requirement 12.5.2 requires entities to document and confirm PCI DSS scope at least once every 12 months and upon significant change to the in-scope environment; Requirement 12.5.2.1 additionally requires service providers to confirm scope at least once every six months and upon significant change.

Both requirements are empirical in an important sense: an entity cannot credibly confirm scope, or demonstrate the absence of retained SAD, without knowing where account data may reside. Card data can accumulate in locations not normally treated as data stores, including application debug logs, browser caches, crash dumps, backup staging directories, CSV exports, and telephony records. Policy alone does not discover these locations.

Commercial data-discovery platforms can address this problem, but they often require substantial infrastructure, persistent agents, and licensing expenditure. Lightweight scanners are positioned as an alternative: small on-device tools that identify candidate payment-card data and produce evidence with limited operational impact. However, vendor claims concerning accuracy, false-positive behaviour, and performance are rarely accompanied by independent, reproducible measurements on a common corpus.

This paper evaluates a lightweight scanner designed for deployment through Active Directory Group Policy, a configuration mechanism already widely available in Windows enterprise environments. We treat the scanner as a measurement instrument rather than a commercial product. The contribution is not a claim that particular regular expressions are optimal; it is a controlled, reproducible comparison of detection effectiveness, operational overhead, false-positive behaviour, and evidence utility.

### Research questions

**RQ1.** How accurately does a lightweight scanner designed for Active Directory Group Policy deployment detect primary account numbers (PANs) and SAD-like artifacts, compared with a scripted baseline using regular-expression extraction and Luhn validation only?

**RQ2.** What operational overhead does the Group Policy deployment model impose, measured through scan throughput, CPU time, and peak resident memory over repeated executions, and modelled through deployment latency under a deterministic refresh-schedule model?

**RQ3.** Which sources dominate false positives, and what is the marginal effect of issuer identification number (IIN) and length validation beyond Luhn validation?

### Contributions

- A controlled, reproducible evaluation of a lightweight, Group Policy–deployed endpoint scanner for PAN and SAD-like artifact detection.
- A deterministic synthetic corpus generator and manifest-based ground-truth design that avoids the use of real cardholder data.
- A versioned IIN and length-validation rule set, with an explicit analysis of its precision–recall trade-off.
- An open artifact comprising the scanner, Group Policy bootstrap script, corpus generator, evaluation harness, raw result files, and reproduction instructions.

## 2. Related Work

Three research and practice areas are relevant: PCI DSS measurement studies, endpoint data-discovery tools, and directory-based software deployment.

### PCI DSS measurement studies

Prior work on compliance measurement has emphasised that self-assessment and formal scope declarations may not reflect the actual distribution of cardholder data across an environment [9, 10]. Industry-wide surveys repeatedly find that declared scope diverges from observed data locations, and that automated discovery can reveal account data in locations that organisations had classified as out of scope [11]. The methodological implication is that compliance evidence benefits from independent instrumentation; the practical implication is that scope documentation must be validated against observed data locations and flows.

### Endpoint data-discovery tools

Commercial lightweight scanners are marketed to enterprises with on-device scanning, Luhn-based candidate filtering, and low performance overhead advertised as central properties. Public comparative evidence is often limited to feature comparisons or vendor-authored material rather than controlled accuracy measurements on a shared corpus. Where independent evaluations exist, they tend to examine individual tools rather than compare detection conditions under a common ground truth.

### Directory-based deployment

Group Policy software installation and startup-script assignment are established mechanisms for distributing scripts and lightweight agents across Windows domains [13]. Their advantages include broad reach within linked organisational units and minimal additional management infrastructure. Their limitations include dependence on organisational-unit structure, network-share availability, computer-account permissions, and policy-refresh scheduling.

### Gap

To our knowledge, no peer-reviewed reproducible evaluation compares an Active Directory–deployed lightweight scanner with a controlled Luhn-only baseline on both detection accuracy and operational overhead under the evidence expectations of PCI DSS v4.0.1. This study addresses that gap and releases an artifact sufficient for independent re-execution.

## 3. Background

### 3.1 Cardholder data and sensitive authentication data

PCI DSS distinguishes account data into cardholder data and sensitive authentication data. Cardholder data includes the PAN and may include the cardholder name, expiration date, and service code. SAD includes full magnetic-stripe data, card verification codes, and PINs or PIN blocks.

The regulatory asymmetry is central to this study. A PAN may be stored if it is rendered unreadable in accordance with PCI DSS, whereas SAD must not be retained after authorization. Consequently, PAN detection and SAD detection are not interchangeable outcomes. A PAN finding is primarily a scoping and inventory input; a SAD finding indicates a potential control failure and should trigger incident-oriented triage.

### 3.2 Luhn validation and issuer validation

The Luhn algorithm [5] computes a modulo-10 checksum over a numeric string and is commonly used as a first-stage filter for candidate PANs. It is necessary but insufficient: a substantial proportion of random numeric strings of card-like length satisfy the checksum. On numeric-dense corpora containing timestamps, order identifiers, telephone numbers, and sequential keys, Luhn-only detection can produce material false-positive rates.

IIN prefixes and issued-length rules provide a second-stage filter. Under ISO/IEC 7812 [3], the leading digits of a payment card number identify the issuing industry and issuer. Combining Luhn validation with IIN and length validation can reduce false positives, but it can also exclude valid PANs whose issuer ranges are absent from the configured rule set.

#### 3.2.1 Issuer-validation rule set

The IIN and length rules used in this study are fully specified in Table 1 and are versioned in the artifact as `iin_rules-v1.0.json` (accessed August 2025). A candidate is classified as a PAN if and only if it satisfies all of the following:

1. It passes the Luhn checksum.
2. Its digit length falls within the issued-length range associated with a recognised prefix.
3. Its prefix matches an entry in Table 1.

A Luhn-valid candidate that matches no configured prefix is recorded with detection class `unmatched_luhn_valid` and excluded from the PAN-positive class. This is the deliberate recall penalty of using an allowlist rather than accepting every Luhn-valid string.

**Table 1. Issuer-validation rule set, version 1.0.**

| Brand | Prefix range | Accepted lengths |
|---|---|---|
| Visa | 4 | 13, 16, 19 |
| Mastercard | 51–55; 2221–2720 | 16 |
| American Express | 34; 37 | 15 |
| Discover | 6011; 644–649; 65 | 16–19 |
| JCB | 3528–3589 | 16–19 |
| UnionPay | 62 | 16–19 |
| Maestro | 5018; 5020; 5038; 5893; 6304; 6759; 6761; 6762; 6763 | 12–19 |
| Diners Club | 300–305; 3095; 36; 38–39 | 14–19 |

Where prefix ranges overlap across brands, the most specific matching prefix takes precedence. Overlapping ranges, precedence order, and the exact machine-readable rule file are included in the artifact. The rule set was compiled from ISO/IEC 7812-1 [3] and publicly documented issuer-network range references current as of August 2025, following industry practice in which checksum-based first-stage filtering [5] is combined with prefix and length governance under ISO/IEC 7812 [3]. Because IIN allocations change, the study does not claim that the rule set is exhaustive or current beyond that date. Private-label cards and newly issued prefixes may not be represented; their absence is an expected source of false negatives introduced by validation.

### 3.3 Active Directory Group Policy deployment model

The evaluated deployment model uses a PowerShell bootstrap script assigned as a computer startup script through Group Policy. On execution, the script retrieves the current scanner version from a network share, executes it against a configured scan root, writes JSON Lines output to a per-host directory on a results share, and records a completion marker after the scan for reporting.

The model requires no persistent service, no dedicated agent-management plane, and no local administrative installation beyond the bootstrap script and an available Python interpreter. Reach is determined by Group Policy linkage; version control is achieved by replacing the scanner on the tool share.

## 4. Methodology

### 4.1 Research design

We conduct a controlled comparative experiment with three conditions [8]:

- **Condition P — proposed scanner:** regular-expression extraction, Luhn validation, and IIN/length validation, executed through the Group Policy bootstrap.
- **Condition A — Luhn-only baseline:** an otherwise identical scanner with IIN and length validation disabled.
- **Condition B — cross-check scanner:** an independent cross-check implementation, used to detect implementation-specific artifacts in Condition P's results.

All conditions scan the identical corpus, use the identical ground-truth manifest, and execute on identical hardware. Scan-overhead components (throughput, CPU time, peak memory, result size, and scan failure rate) are measured over 30 repetitions per condition on the reference endpoint, with the first local execution discarded as a warm-up run to reduce the influence of cold file-system caches and first-run process startup.

Group Policy bootstrap deployment latency is not measured on a live estate in this study; it is produced by a deterministic refresh-schedule model that implements the Appendix C protocol — 20 simulated policy-refresh cycles per endpoint across 10 modelled endpoints, yielding 200 observations, each recording the time from policy-refresh initiation to simulated scanner start (bootstrap completion), excluding scan execution, with failed cycles retained and reported. The modelled block is labelled as such wherever it appears (abstract, §6.2, §7, Appendix C) and its validity is discussed in §8. Executing the same protocol on a live AD estate is prescribed as the immediate extension of this work.

Medians, interquartile ranges, and full distributions are reported. No claim is made about overhead differences that fall within the measured interquartile range.

### 4.2 Metrics

Detection performance is reported at the file level, the granularity at which compliance evidence is produced. For each condition and detector class, we report true positives (TP), false positives (FP), false negatives (FN), true negatives (TN), true-positive rate/recall, false-positive rate, precision, and F1 score.

$$TPR = Recall = \frac{TP}{TP + FN} \qquad FPR = \frac{FP}{FP + TN}$$

$$Precision = \frac{TP}{TP + FP} \qquad F_1 = \frac{2 \cdot Precision \cdot Recall}{Precision + Recall}$$

Because TPR and FPR are proportions estimated from a finite corpus, Wilson score 95% confidence intervals [6] are reported. Paired file-level outcomes between Conditions P and A are compared using McNemar's test [7].

Operational overhead is reported following security-control measurement guidance [12]:

- Bootstrap deployment latency, from policy-refresh initiation to scanner start (bootstrap completion), excluding scan execution.
- Scan throughput in seconds per gigabyte.
- Total CPU time.
- Peak resident set size.
- Result-file size per gigabyte scanned.
- Deployment and scan failure rate.

Compliance utility is assessed against five evidence attributes defined in this study: host identifier, absolute file path, masked PAN revealing only the final four digits, detection-class label distinguishing PAN from SAD, and ISO 8601 timestamp.

### 4.3 Ground truth

No real cardholder data is used. The corpus is produced by a deterministic generator with a fixed seed and emits each file together with an entry in `manifest.json` recording whether it contains ground-truth PAN data and whether it contains ground-truth SAD-like data. The manifest is the sole source of truth; labels are never embedded in file content.

The corpus contains five classes:

1. **Valid-PAN files:** synthetic PANs from published test BIN ranges across Visa, Mastercard, American Express, and Discover, rendered in plain, space-separated, hyphen-separated, and line-split forms; a designated subpopulation (~3% of PAN-positive files) additionally uses issued-like ranges absent from rule set version 1.0 (private-label-like), exercising the expected recall penalty of the allowlist.
2. **Luhn-invalid numeric files:** 13–19 digit strings that fail the checksum.
3. **Luhn-valid non-card files:** numeric identifiers that satisfy Luhn by chance but either do not match a configured IIN prefix (majority) or deliberately match a recognised prefix while not being cardholder data (a documented adversarial subpopulation).
4. **SAD-bearing files:** plaintext Track 1-like and Track 2-like records, with and without discretionary data, plus card-verification-code contexts.
5. **Benign control files:** prose, log lines containing dates and telephone numbers, small binary blobs, non-card numeric identifiers, and adversarial SAD keyword–digit proximity records that are not SAD.

Track 2 variants are generated both with and without the leading `;` sentinel, because application logging frequently strips or omits the sentinel while retaining the remainder of the record.

At the file level of this corpus, 5,000 files constitute the ground truth, of which 588 are PAN-positive (500 standalone valid-PAN files plus 88 CVV-context files that also contain a standalone PAN) and 4,100 are PAN-negative, non-SAD. The 400 SAD-bearing files split into CVV-context records containing a standalone PAN (88 files, therefore also PAN-positive) and Track 1/Track 2 records whose card number appears only inside the track structure (312 files). Those 312 files are ground-truth SAD but are excluded from both the PAN-positive and PAN-negative sets, because PCI DSS Requirement 3.3.1 classifies full track data as SAD: an account number embedded inside a Track 1 or Track 2 record is not treated as a routine PAN inventory finding, it is a potential control failure that should trigger incident triage. The scanner therefore emits these records as SAD findings rather than PAN findings. This is why Table 2 and Table 3 use different denominators (588 positives / 4,100 negatives for PAN detection, versus 5,000 minus the per-class SAD-positive count for each SAD class). The classification decision reflects the regulatory distinction between PAN inventory and SAD evidence, not a gap in detection coverage.

A circularity threat exists because the corpus generator and detection patterns are authored by the same research team. We mitigate it in three ways. First, SAD-like strings are generated in multiple formats derived from ISO/IEC 7813 [4] rather than from a single template. Second, the generator and scanner are maintained as independent modules with no shared constants. Third, Condition B provides a cross-check against an implementation sharing no code with Condition P. Residual circularity is acknowledged in Section 8.

### 4.4 Experimental environment

All measured scan experiments are conducted on a single designated reference endpoint running Windows 11 (build 10.0.26200) and Python 3.14.5, with tool and results shares hosted on a Windows Server 2019 file server. This single-host design ensures that hardware and scheduling variance cannot confound the accuracy or overhead comparisons in Tables 2–4. The corpus contains 5,000 files totalling 0.0269 GB (26.9 MB). Python 3.14.5 was the runtime used for assembling the public artifact; the detection results reported here are invariant to the verification runtime.

Because a live Active Directory estate with multiple domain-joined endpoints was not available, the Group Policy deployment-latency protocol (Appendix C) was executed as a deterministic refresh-schedule model. The modelled deployment environment assumes a single Active Directory forest at functional level Windows Server 2016, with domain controllers running Windows Server 2019, and 10 modelled endpoints under the linked organisational-unit scope.

Hardware specifications, Group Policy settings, share permissions, scanner versions, and raw timing data for the measured components are included in the artifact (`results/environment.json`; output checksums in `results/reproduction_receipt.txt`). The model parameters for the deployment-latency component are included in `results/overhead.json`.

## 5. Implementation

### 5.1 Architecture

The system comprises four components:

1. A Group Policy–assigned PowerShell bootstrap script.
2. A standard-library-only Python scanner.
3. A deterministic corpus generator.
4. An evaluation harness that computes all reported metrics from the manifest and scanner output.

The scanner performs file enumeration, candidate extraction, Luhn validation, issuer and length validation, and masked JSONL serialisation.

### 5.2 Scanner design

The scanner is restricted to the Python standard library so that the artifact can be audited and executed without dependency resolution. Three design constraints are explicit.

First, per-file reads are bounded by a configurable maximum byte count, defaulting to 5 MiB. This preserves the lightweight property but creates a coverage limitation: content beyond the cap is not examined. The cap was not exercised by the synthetic corpus (maximum file size ≈20 KiB), so its effect on recall is untested.

Second, all PAN output is masked to the final four digits at the point of detection. Unmasked PANs do not reach the results share.

Third, SAD findings are emitted with an explicit escalation flag and a distinct detection class. The collector routes flagged records to an incident queue rather than to routine inventory.

SAD-like detection is deliberately narrow and is scoped to plaintext Track 1 and Track 2 records in file content, plus the CVV/CVC context rule below. The implemented patterns cover:

- Track 1 records of the form `%B…^…/…^…?`, with and without discretionary data; the trailing `?` terminator is optional to accommodate truncated logs.
- Track 2 records of the form `;…=…?`, with and without discretionary data; the trailing `?` terminator is optional for the same reason.
- Card-verification-code context, where a case-insensitive `cvv`, `cvc`, or `cid` keyword is followed within 0–40 non-digit, non-newline characters by a three- or four-digit value (implemented as `(?i)\b(?:cvv|cvc|cid)\b[^0-9\n]{0,40}(\d{3,4})\b`).
- Track 2 detection accepts records both with and without the leading `;` sentinel.

Three coverage limits are explicit and excluded from the SAD-like recall claim:

- Base64- and hex-encoded track-like strings are not decoded and are not detected.
- SAD present only in process memory, encrypted containers, database pages not materialised to files, or content beyond the per-file byte cap is not detected.
- Partially corrupted or reformatted records that do not conform to Track 1 or Track 2 field structure may under-match.

### 5.3 Group Policy deployment

The bootstrap script is assigned under Computer Configuration → Policies → Windows Settings → Scripts → Startup and linked to the target organisational unit. On execution, it:

1. Ensures a local installation directory.
2. Copies the current scanner from the tool share.
3. Executes the scan against the configured root.
4. Uploads JSONL output to a per-host directory on the results share.
5. Writes a completion marker after the scan for reporting (not part of the measured bootstrap latency).

Access control relies on the computer account's read permission on the tool share and write permission on the results share. For large populations, the script may instead be assigned as an immediate scheduled task with a randomised delay to avoid simultaneous execution across the estate.

Because the bootstrap executes in the local SYSTEM context through the computer startup policy, the tool share should be read-only to computer accounts, scanner binaries should be hash-verified or signature-verified before execution, and the results share should be write-only or tamper-evident. Executing a scanner as SYSTEM across the estate also concentrates risk: a compromised tool share would execute with that privilege on every linked endpoint. The deployment script does not itself enforce these controls; they are configuration requirements for production use and are outside the detection evaluation.

## 6. Results

### 6.1 Detection performance

**Table 2. File-level PAN detection performance, with Wilson 95% confidence intervals.**
*Denominators: n = 588 PAN-positive files, 4,100 PAN-negative/non-SAD files (see §4.3). The 312 Track-1/Track-2 SAD-only files are outside these sets.*

| Condition | TP | FP | FN | TN | TPR (95% CI) | FPR (95% CI) | Precision | F1 |
|---|---|---|---|---|---|---|---|---|
| P — proposed | 570 | 22 | 18 | 4,078 | 96.94 (95% CI [95.21, 98.06]) | 0.54 (95% CI [0.35, 0.81]) | 96.28 | 96.61 |
| A — Luhn only | 588 | 110 | 0 | 3,990 | 100.00 (95% CI [99.35, 100.00]) | 2.68 (95% CI [2.23, 3.22]) | 84.24 | 91.45 |
| B — cross-check | 475 | 100 | 113 | 4,000 | 80.78 (95% CI [77.40, 83.76]) | 2.44 (95% CI [2.01, 2.96]) | 82.61 | 81.68 |

Condition P detected 570 of 588 PAN-positive files and flagged 22 of 4,100 negative files. Relative to Condition A, Condition P changed TPR by −3.06 percentage points (continuity-corrected McNemar χ² = 16.056, p < 0.0001; discordant pairs: 18 A-only, 0 P-only) and changed FPR by −2.14 percentage points (continuity-corrected McNemar χ² = 86.011, p < 0.0001; discordant pairs: 88 A-only, 0 P-only). Because Condition P applies every Luhn detection that Condition A applies and then filters by IIN, P's PAN detections are a subset of A's, so P-only discordance is structurally zero.

Condition P missed 18 PAN-positive files that Condition A detected (recall −3.06 pp), all attributable to issued ranges absent from rule set v1.0, while removing the 88 A-only false positives and retaining the 22 shared false positives. The recall loss is the designed, bounded penalty of the allowlist; the precision gain is concentrated exactly where Luhn-only detection is weakest, on numeric-dense non-card content. The F1 advantage of Condition P (96.61 vs 91.45) is the summary effect: on this corpus the precision bought by issuer validation outweighs the recall it costs.

**Table 3. File-level SAD-like detection performance for Condition P within the implemented plaintext envelope.**
*Denominators per row: SAD-positive files of that class (Track 1: 155; Track 2: 157; CVV/CVC: 88) and the remaining 5,000 files as negatives for that class.*

| SAD class | TP | FP | FN | TN | TPR (95% CI) | FPR (95% CI) | Precision | F1 |
|---|---|---|---|---|---|---|---|---|
| Track 1-like | 155 | 0 | 0 | 4,845 | 100.00 (95% CI [97.58, 100.00]) | 0.00 (95% CI [0.00, 0.08]) | 100.00 | 100.00 |
| Track 2-like | 157 | 0 | 0 | 4,843 | 100.00 (95% CI [97.61, 100.00]) | 0.00 (95% CI [0.00, 0.08]) | 100.00 | 100.00 |
| CVV/CVC context | 88 | 540 | 0 | 4,372 | 100.00 (95% CI [95.82, 100.00]) | 10.99 (95% CI [10.15, 11.90]) | 14.01 | 24.58 |

Track-type SAD-like recall within the implemented envelope is 100.00 for both track classes, with zero false positives, as expected by construction; this is not evidence of real-world recall. CVV/CVC context detection reaches 100.00 TPR but only 14.01% precision (F1 = 24.58%) at 10.99% FPR, driven by the adversarial keyword-proximity records in the corpus. The 540 CVV/CVC false positives mean many ordinary files would generate SAD alerts, creating a material triage burden in a security-operations environment. SAD-like recall of 100.00% is an optimistic estimate of real-world recall. The synthetic corpus exercises exactly the plaintext Track 1 and Track 2 formats implemented by the detector, and therefore measures performance within the detector's coverage envelope. It does not estimate detection performance on encrypted, in-memory, database-resident, or otherwise unmaterialised SAD, nor on encoded track-like strings, which are outside the detector's scope as stated in Section 5.2.

### 6.2 Operational overhead

**Table 4. Operational overhead.**

| Metric | Condition P | Condition A | Condition B |
|---|---|---|---|
| Median scan throughput, s/GB | 3.08 | 3.14 | 294.02 |
| Median CPU time, s | 0.063 | 0.078 | 7.81 |
| Median peak resident memory, MB | 17.96 | 18.06 | 25.02 |
| Median result size, MB/GB scanned | 14.26 | 14.23 | 6.26 |
| Scan failure rate (30 repetitions per condition) | 0.00 | 0.00 | 0.00 |

*Note: medians are reported in this table; interquartile ranges and per-repetition distributions for scan throughput, CPU time, peak RSS, and result size are available in `results/overhead.json`.*

**Deployment-latency cohort (deterministic modelled block; see §4.1, §8):** 10 modelled endpoints × 20 simulated policy-refresh cycles = 200 observations; median 43.3 s over all 200 cycles (IQR 36.1–50.1, min 27.4, max 86.1; 43.0 s over the 194 successful cycles); 6 failed cycles (3.0%), distributed across 4 of the 10 modelled endpoints (two endpoints with one failure each, two with two failures each); every endpoint completed at least 18 of 20 cycles, so all 10 endpoints were reached (an endpoint is counted as reached if at least one of its cycles completed). The model is shared by P and A (and B, since reach does not differ by engine).

A throughput of 3.08 seconds per gigabyte implies an approximate full-scan duration of 370 seconds (about 6.2 minutes) for a 120 GB endpoint. This is compatible with the maintenance window assumed for the studied environment. Peak resident memory of 17.96 MB is consistent with the lightweight designation operationalised in this study: no persistent service, no dedicated agent infrastructure, and no measurable interactive impact beyond the measured scan process.

Notably, the independently implemented Condition B scanner ran approximately 95× slower than Conditions P and A on identical input, demonstrating that "natural-looking" implementation choices (naïve re-scanning and per-record serialisation) can dominate runtime, and reinforcing the value of measuring overhead rather than assuming it.

### 6.3 False-positive analysis

False positives were classified into four mutually exclusive categories. Categories 1–3 are PAN-level false positives; category 4 is a SAD-level false positive produced by the CVV/CVC proximity heuristic (which emits a SAD record, not a PAN record).

**Table 5a. PAN-level false positives, classified by source.**
*Denominator: the condition's PAN-level FP count over the 4,100 PAN-negative files (Condition P: 22; Condition A: 110). Percentages are of that panel total.*

| False-positive source | Condition P count | Condition P % | Condition A count | Condition A % |
|---|---|---|---|---|
| Luhn-passing non-card number | 21 | 95.5 | 21 | 19.1 |
| Card-like numeric identifier with no recognised IIN | 0 | 0.0 | 79 | 71.8 |
| Partial match in binary or encoded content | 1 | 4.5 | 10 | 9.1 |
| **PAN-level total** | **22** | **100** | **110** | **100** |

**Table 5b. SAD-level false positives (CVV/CVC proximity heuristic).**
*Denominator: 4,912 files without CVV/CVC ground truth (5,000 − 88); 540 is the CVV-context over-match, the only SAD-level FP source. Conditions P and A share the same SAD detector (only PAN validation differs between them), so both produce the identical 540 over-matches; Condition B does not implement SAD classes.*

| False-positive source | Count | % of non-CVV files |
|---|---|---|
| SAD keyword–digit proximity over-match | 540 | 10.99 |

**Denominator note.** The machine-readable `results/fp_classification.csv` reports the same false-positive counts as Tables 5a and 5b, but computes its percentage column over all false-positive records (including the 540 SAD-level over-matches). Tables 5a and 5b report PAN-level and SAD-level percentages separately, using the denominators stated in each table. All false-positive counts in Tables 5a and 5b are file-level counts.

The 21 category-1 false positives shared by both conditions are the corpus's adversarial subpopulation of Luhn-valid numerals on recognised prefixes placed in non-card files (Section 4.3): they satisfy every rule predicate — checksum, prefix, and length — and issuer validation cannot reject them. This is precisely the allowlist's designed residual error, and it bounds how far precision can rise before prefix-specific context is added.

Adding IIN and length validation eliminated 88 PAN-level false positives (from 110 to 22), a reduction of 80.0% relative to Condition A, at the cost of 18 additional false negatives, equivalent to 3.06 percentage points of recall. The false negatives introduced by validation were concentrated in valid PAN files whose synthetic numbers use issued ranges absent from rule set v1.0 (private-label-like), recorded under detection class `unmatched_luhn_valid`.

The central trade-off of the study is unchanged by the category composition: issuer validation buys precision at the cost of coverage. For inventory and scoping, recall is generally more important; for incident detection, precision and triage cost are more important. Separately, the 540 file-level CVV/CVC over-matches shared by both conditions show that the SAD proximity heuristic is the dominant residual noise source and should be paired with context tightening or human triage — precisely the incident-queue routing already required by the design's escalation flag.

### 6.4 Compliance utility

Every finding record produced by Conditions P and A carried a host identifier, absolute file path, masked PAN, detection-class label, and per-finding ISO 8601 timestamp, satisfying the five evidence attributes defined in Section 4.2. Condition B lacks the PAN/SAD detection-class schema required by the study's evidence rubric, which affects its suitability as evidence (Table 6).

**Table 6. Evidence attributes present in each condition's output.**

| Evidence attribute | Condition P | Condition A | Condition B |
|---|---|---|---|
| Host identifier | Yes | Yes | Yes |
| Absolute file path | Yes | Yes | Yes |
| Masked PAN (final four digits) | Yes | Yes | Yes |
| Detection-class label (PAN vs SAD) | Yes | Yes | **No** |
| ISO 8601 timestamp | Yes (per finding) | Yes (per finding) | Yes (run-level) |

Condition B emits one run-level timestamp rather than a per-finding timestamp, so it is a cross-check implementation rather than a drop-in evidence source under the rubric.

This is a functional difference independent of detection accuracy. A scanner may achieve comparable accuracy while producing output that is less useful for evidence collection or incident triage.

## 7. Discussion

### Answering RQ1

Condition P achieved a PAN TPR of 96.94% (95% CI [95.21, 98.06]) and FPR of 0.54% (95% CI [0.35, 0.81]). Detection is dominated by the precision–recall trade-off introduced by issuer validation: precision on this corpus rises from 84.24 to 96.28 while recall falls 3.06 percentage points; both are within the designed behaviour of an allowlist rule set. F1 improves from 91.45 to 96.61. The cross-check condition underperforms both (TPR 80.78%, FPR 2.44%), which is consistent with its simpler, line-unaware extraction and demonstrates that implementation choices — not just validation policy — materially affect both accuracy columns. Condition B is a cross-check implementation, not a competing scanner; its result demonstrates implementation sensitivity, not that Condition P is superior to all external scanners.

### Answering RQ2

The deterministic deployment-latency model reached all 10 modelled endpoints (each completed at least 18 of 20 simulated policy-refresh cycles) with median modelled bootstrap latency of 43.3 seconds over all 200 cycles (43.0 seconds over the 194 successful cycles). Six of 200 cycles failed (3.0%), distributed across four endpoints (two with one failure each, two with two each); measured scan failure rate over 30 repetitions per condition was 0.00. Conditional on the model's refresh-schedule assumptions, marginal deployment cost within a linked organisational-unit scope is low in an existing AD/GPO environment, although share hosting, permissions management, storage, and operational monitoring still carry cost; endpoints outside the linked scope remain invisible to the scan in either case.

### Answering RQ3

Issuer validation reduced false positives by 80.0% at a recall cost of 3.06 percentage points. The dominant false-positive source is the SAD keyword–digit proximity over-match (540 file-level false positives, shared across conditions), while at the PAN level the Luhn-only baseline's dominant FP category was card-like numeric identifiers with no recognised IIN (79 of 110), precisely the class issuer validation removes. This quantifies, in a PCI DSS context, the limitation of Luhn-only detection on numeric-dense corpora.

### Compliance implications

Two findings have direct assessment relevance. First, SAD findings should be triaged as incident evidence rather than routine inventory; this is a requirement on the output schema, not merely an operational preference. Second, scanner output alone does not discharge Requirements 3.3.1 or 12.5.2. An assessor may also examine policies, procedures, system configurations, data-flow diagrams, scoping sign-off records, deletion records, and post-remediation re-scan evidence. The scanner supplies location evidence that makes those artifacts verifiable; it does not substitute for them.

### Coverage limitations

The bounded per-file read, text-decoding path, and absence of in-memory inspection jointly define the scanner's coverage envelope. Within that envelope, the scanner is fast and deployable. Outside it, the scanner is silent rather than wrong. Silence can be mistaken for absence of data, which is the more dangerous failure mode for compliance evidence.

## 8. Threats to Validity

### Internal validity

The principal internal threat is circularity between corpus generation and pattern design. We mitigate it through independent derivation of SAD patterns from ISO/IEC 7813 [4], separation of generator and scanner modules, and a cross-check condition. Residual circularity cannot be eliminated; SAD-like recall should therefore be interpreted as an optimistic estimate within the implemented coverage envelope.

A secondary threat is configuration sensitivity. Results depend on the per-file byte cap, scan root, IIN rule version, and Track 2 sentinel handling. All configuration files, rule versions, and raw outputs are included in the artifact.

### External validity

The study covers Windows endpoints in a single Active Directory forest at one functional level. Generalisation to Linux, macOS, multi-forest environments, cloud workspaces, containers, and non-domain-joined systems is untested. The synthetic corpus is structurally diverse but cannot represent the full distribution of real file content; production data would likely produce lower recall and a different false-positive composition.

### Construct validity

"Lightweight" is operationalised as the absence of a persistent service or dedicated agent infrastructure, combined with measured CPU, memory, deployment, and throughput overhead. Other definitions, such as network bandwidth during deployment or user-perceptible interactive latency, may yield different conclusions.

### Conclusion validity

Wilson confidence intervals and paired McNemar tests are reported, but finite corpus size produces non-trivial interval width. Small differences between conditions should not be interpreted as established effects. Masking and per-file byte-cap choices may also affect the acceptability of output as assessment evidence under a stricter rubric.

### Model invalidity of the deployment-latency input

Deployment latency, reach, and deployment failure rate (§6.2 deployment-latency cohort, §7 RQ2, Appendix C) come from a deterministic refresh-schedule model, not from measurement on a live Active Directory estate. The modelled interval ends at scanner start and excludes scan execution; endpoint reach is derived from simulated cycle-completion counts. The model encodes a plausible policy-refresh-plus-share-copy delay distribution but does not capture real GPO behaviours — background refresh cadence variance, network-share contention on mass application, machine-account permission failures across heterogeneous baselines, and enterprise scheduling (e.g., randomised delays at scale). Conclusions about deployment overhead are therefore conditional on model assumptions and are reported as modelled, not measured. Executing the Appendix C protocol on a live estate is the designated next step and would prompt direct replacement of the modelled block; until then, no latency claim from this study should be read as field-validated.

## 9. Conclusion and Future Work

This paper presented a comparative evaluation of a lightweight endpoint scanner designed for Active Directory Group Policy deployment for PCI DSS cardholder-data detection. Against a deterministic synthetic corpus, the scanner achieved a 96.94% PAN true-positive rate and a 0.54% false-positive rate. Issuer and length validation reduced false positives by 80.0% at a recall cost of 3.06 percentage points. Under the deterministic refresh-schedule model, the modelled Group Policy deployment pathway shows low marginal infrastructure cost within the linked scope while leaving out-of-scope endpoints unscanned; field measurement of that model on a live estate remains designated future work.

Future work should first replace the deterministic deployment-latency model with the Appendix C protocol executed on a live estate; it should then extend detection to non-textual and in-memory SAD surfaces; compare agentless network-based discovery with the agent-based model evaluated here; validate output against an assessor-reviewed evidence rubric rather than a synthetic manifest; and measure false-positive drift as production file populations change.

## References

1. PCI Security Standards Council. Payment Card Industry Data Security Standard, Version 4.0.1. June 2024.
2. PCI Security Standards Council. Payment Card Industry Data Security Standard, Version 4.0. March 2022.
3. ISO/IEC 7812-1:2017. Identification cards — Identification of issuers — Part 1: Numbering system.
4. ISO/IEC 7813:2006. Information technology — Identification cards — Financial transaction cards.
5. Luhn, H. P. Computer for Verifying Numbers. U.S. Patent 2,950,048, 1960.
6. Wilson, E. B. "Probable Inference, the Law of Succession, and Statistical Inference." Journal of the American Statistical Association, 22(158), 1927.
7. McNemar, Q. "Note on the Sampling Error of the Difference Between Correlated Proportions or Percentages." Psychometrika, 12(2), 1947.
8. Wohlin, C., Runeson, P., Höst, M., Ohlsson, M. C., Regnell, B., and Wesslén, A. Experimentation in Software Engineering. Springer, 2012.
9. PCI Security Standards Council. PCI DSS Scoping Guidance. November 2016.
10. Verizon Business. Verizon 2020 PCI Compliance Report. 2020.
11. SANS Institute. The 2020 SANS PCI Compliance Survey. 2020.
12. NIST. Performance Measurement Guide for Information Security. NIST Special Publication 800-55, Revision 1, July 2008.
13. Microsoft. Group Policy overview. Microsoft Learn documentation.

*Note: the Condition B cross-check scanner is deliberately not a numbered reference; it is part of this study's released artifact (Appendix B), not an external citation.*

## Appendix A — Exact reproduction procedure

```bash
# 1. Generate and freeze the corpus
python corpus/generate_corpus.py --out corpus --files 5000 --seed 42

# 2. Condition P: proposed scanner
python scanner/lightweight_pci_scanner.py corpus \
  --config configs/condition_P.json \
  --out results/condition_P/scan_results.jsonl

# 3. Condition A: Luhn-only baseline
python scanner/lightweight_pci_scanner.py corpus \
  --config configs/condition_A.json \
  --out results/condition_A/scan_results.jsonl

# 4. Condition B: independent cross-check scanner
python evaluation/cross_check_scanner.py corpus \
  --out results/condition_B/scan_results.jsonl

# 5. Metrics, confidence intervals, McNemar tests
python evaluation/evaluate_scanner.py \
  --manifest corpus/manifest.json \
  --conditions results/condition_P results/condition_A results/condition_B \
  --out results/metrics.json

# 6. Overhead protocol (1 warm-up + 30 measured repetitions per condition)
python evaluation/resource_monitor.py \
  --corpus corpus \
  --out results/overhead.json

# 7. Generate every manuscript fill-point
python evaluation/make_tables.py \
  --metrics results/metrics.json \
  --overhead results/overhead.json \
  --false-positives results/fp_classification.csv \
  --out paper/manuscript_fillpoints.json
```

**Verification receipt:** `results/reproduction_receipt.txt` records the SHA-256 hashes of `metrics.json`, `overhead.json`, `fp_classification.csv`, the three condition outputs, and `corpus/manifest.json` from the runs used in this manuscript, together with host and Python version. On a fresh Windows checkout, re-running steps 1–6 and comparing hashes verifies the tables (determinism requires identical Python 3.x, identical Windows text encoding, and fixed corpus seed 42; note steps 4 and 6 are timing-dependent and byte-identical JSONL timestamps/lines may differ, in which case compare record counts and metrics.json values instead of raw hashes). Invoke all commands from the artifact root (`configs/` is read by relative path).

Note: the deployment-latency inputs to Appendix C (10 endpoints × 20 cycles) are produced by the deterministic demo model inside `resource_monitor.py`; on a live AD estate, execute the Appendix C protocol directly.

## Appendix B — Artifact contents

```text
pci-scanner-artifact/
├── README.md
├── LICENSE
├── scanner/
│   ├── lightweight_pci_scanner.py
│   └── iin_rules-v1.0.json
├── deployment/
│   ├── Deploy-LightweightScanner.ps1
│   └── GPO-configuration.md
├── corpus/
│   ├── generate_corpus.py
│   └── manifest_schema.json
├── evaluation/
│   ├── evaluate_scanner.py
│   ├── make_tables.py
│   ├── statistical_tests.py
│   ├── cross_check_scanner.py
│   └── resource_monitor.py
├── configs/
│   ├── condition_P.json
│   ├── condition_A.json
│   └── condition_B.json
├── results/
│   ├── metrics.json
│   ├── overhead.json
│   ├── fp_classification.csv
│   └── environment.json
└── paper/
    ├── manuscript.md
    └── manuscript_fillpoints.json
```

The Condition B cross-check scanner (`evaluation/cross_check_scanner.py`, version 0.2) is an independent implementation released as part of this artifact; it is intentionally not a numbered reference because it has no external source.

## Appendix C — Deployment-latency protocol (executed as a deterministic refresh-schedule model; see §4.1 and §8)

```text
Modelled endpoints:                10
Modelled cycles per endpoint:      20
Total modelled observations:       200
Measured interval (modelled):      policy-refresh initiation
                                   to scanner start (bootstrap
                                   completion), excluding scan
                                   execution
Failure handling:                  retained and reported separately
Model output:                      median 43.3 s over all 200 cycles,
                                   IQR 36.1–50.1 s, min 27.4 s,
                                   max 86.1 s; median 43.0 s over the
                                   194 successful cycles; 6 failed
                                   refresh cycles (3.0%), distributed
                                   across 4 of 10 endpoints (two with
                                   one failure, two with two); every
                                   endpoint completed at least 18/20
                                   cycles, so all 10 endpoints reached
Live-estate substitution:          run the identical protocol on a
                                   real AD estate to replace this
                                   block (designated future work)
```

## Appendix D — Fill-point mapping

| Manuscript fill-point | Source |
|---|---|
| M, P, Q counts | generated results → corpus/manifest.json (5,000 / 588 / 4,100) |
| Table 2 cells | results/metrics.json → pan_detection |
| Wilson confidence intervals | results/metrics.json → wilson_95_ci_* |
| Table 3 SAD metrics | results/metrics.json → sad_detection |
| McNemar statistics | results/metrics.json → paired_tests |
| Table 4 overhead metrics | results/overhead.json → conditions.* measurement block |
| Deployment-latency model (Appendix C) | results/overhead.json → deployment_latency (deterministic refresh-schedule model; §4.1, §8) |
| False-positive percentages | results/fp_classification.csv |
| IIN access date | scanner/iin_rules-v1.0.json → accessed (August 2025) |
| Environment values | results/environment.json |
| Condition B reference | configs/condition_B.json → scanner_reference; artifact release in this package |
| All fill-points as JSON | paper/manuscript_fillpoints.json |

## Appendix E — Document history and data availability

**Version history**

| Version | Date | Changes |
|---|---|---|
| v1.0 | August 2025 | Completion of the research paper and reproducibility artifact. |

**Data and artifact availability.** The scanner, Group Policy bootstrap script, deterministic corpus generator, evaluation harness, raw results, and reproduction instructions are released as a reproducibility artifact accompanying this paper. Author: Akash Dev, Daffodil International University. Public link: https://github.com/akash-dev2/pci-dss-endpoint-scanner.
