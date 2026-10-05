# Successor research and proposed plan — October 5, 2026

Status: research/planning only. No successor code or project directory created.
Proposed directory: `archive-metadata-risk-lab/` beside this project.
Tier 3: security-focused portfolio learning.

Authorization provenance: authentic user turns in coordinator chat
01a10a45-1a24-78b3-9cef-7c461a966d26 were inspected. Jake delegated approval/start
of further work and then requested more labs after completions. The coordinator
asks this workstream for two candidates and a concrete saved plan; its review
of this plan is still required before successor implementation. Existing local
work is complete; manual review/publication limits are not waived. No dispatch
after 08:00 Eastern October 6, 2026.

## Candidates and reuse check

| Candidate | New learning area | Tradeoff |
| --- | --- | --- |
| ZIP metadata risk analysis | Untrusted archive ingestion, resource budgets and path/entry ambiguity without extraction | Metadata cannot establish actual payload or extraction safety |
| CSV formula-injection handling | Distinguish ordinary text from spreadsheet execution semantics in exports | Consumer behavior/reopening varies; a universal safe-CSV claim would be misleading |

Recommendation: build the bounded ZIP metadata lab. It adds an ingestion area
separate from this broker and the other workstream's AI firewall. The coordinator
must check cross-workstream overlap before approving it.

Local reuse searched: relevant top-level project names, constrained archive/ZIP/
CSV filename searches outside private/vendor/GLPI areas, and keyword searches in
the selected vault. Existing CSV fixtures were found in other portfolio labs;
no dedicated archive-metadata or CSV-formula lab was identified by those searches.
This is not an exhaustive inventory. Coordinator SUCCESSORS.md was read; static
pickle inspection and TLS validation are already assigned elsewhere and avoided.
This lab's JSON evidence, fixed reason codes, bounded parser tests, security
workflow review and reporting concepts can be reused; do not copy its tool
registry or invent an archive execution tool inside it.

## Public-source review and adoption decision

- [Python zipfile documentation](https://docs.python.org/3/library/zipfile.html)
  documents member metadata, caller filename validation for zipfile.Path and
  resource/filesystem pitfalls during decompression. Adopt standard-library
  ZipFile over a bounded in-memory byte buffer for metadata inspection only;
  do not use member open/read/extract/testzip or recursive decompression.
- [Didier Stevens zipdump.py source](https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/zipdump.py)
  is a broad ZIP analysis utility. The source header declares public-domain
  release and version 0.0.36/date 2026-07-30; source includes metadata listing,
  decompression/content output and optional pyzipper/YARA imports. Useful
  comparison/reference, but its wider capabilities are unnecessary here. Build
  a smaller original analyzer rather than fork/run it. If borrowing later,
  preserve clear attribution even where public-domain terms permit reuse.
- [Upstream repository](https://github.com/DidierStevens/DidierStevensSuite)
  was inspected alongside the actual source/manual. Issue/commit/workflow pages
  were attempted but unavailable through the browsing tool. Tests/CI and recent
  issue-specific security status remain unverified; neither stars nor a recent
  source date proves safety. No third-party tool was installed or executed.
- [OWASP CSV Injection](https://community.owasp.org/attacks/CSV_Injection) and
  its [reopen-behavior issue](https://github.com/OWASP/www-community/issues/517)
  support the alternate output-safety exercise and its consumer-specific limits.

No connected GitHub integration is exposed; public primary sources were used.
Firecrawl account metadata previously failed, so the available web tool supplied
research. No paid call, new dependency/provider or external testing is proposed.

## Problem and success criteria

Show why an archive's entry names, permissions and declared sizes require
validation before an application even considers extraction. Given bounded
synthetic ZIP bytes, report entry metadata and explicit risk reasons, or reject
malformed/unsupported input. Demonstrate no member content is decompressed,
opened, executed or written. A clean metadata report never certifies a safe ZIP.

## Scope and architecture

CLI demo and reusable Python analyzer with standard-library runtime only:
bounded raw bytes -> ZipFile(BytesIO(...)) metadata -> conservative policy checks
-> bounded JSON report and fixed reason codes. Inputs are inert synthetic
fixtures; stdin analysis may accept caller-supplied bytes only within the same
size bound. No HTTP service, plugins, passwords, malware download, extraction,
payload reading, Office launch, model inference, filesystem mutation by archive
members, recursive archive traversal or network access.

Initial design budgets (to be tested, not measured performance guarantees):
64 KiB input before constructing ZipFile; at most 16 reported entries; 256 KiB
declared uncompressed bytes per entry; 1 MiB declared total; ratio threshold 100.
Central-directory metadata can lie, so these are policy/triage indicators rather
than a decompression safety boundary. Reject/flag unsupported encryption/methods,
path traversal and absolute/drive/UNC names, backslash ambiguity, NUL/control
characters, Windows reserved/alternate-stream names, symlink attributes and
duplicate/case-normalized name collisions. Inspect original names before any
parser normalization/truncation; escape strings in JSON output.

## Threat model and risks

Attacker controls archive bytes and all metadata. Protect the host from archive
member file writes, decompression/resource amplification and misleading reports.
Trusted: reviewed analyzer, Python runtime and fixture-generation code. Prevent
extraction by omitting that capability entirely. Bound input before parsing,
bound report work and fail closed on parser exceptions. Tests patch member-open,
decompression and extraction paths to fail if called. Use declared-size/ratio
fixtures rather than real decompression bombs.

Remaining risks: malformed metadata, parser implementation vulnerabilities,
Unicode/path aliases and false reassurance from metadata-only results. This
bounded synthetic host exercise is not a malware-analysis sandbox. Real unknown
samples require a separately reviewed disposable VM and are outside this plan.
Payload CRC/content validity and extraction destination safety are not assessed.

## Stages and definitions of done

1. Metadata core: reusable bounded-byte analyzer, deterministic risk codes,
   accepted ordinary synthetic ZIP and denied malformed/over-limit cases.
2. Adversarial fixtures/CLI: path/alias/symlink/encryption/declared-size cases,
   duplicate handling and escaped reports; prove zero member reads/extractions.
3. Review/portfolio: affected tests, available Bandit/ECC review, exact evidence,
   README/threat model/license/AI disclosure and state/decision/learning records.
   Prepare owned-repository baseline locally; no remote publication or merge.

Verification must distinguish metadata findings from payload validation. Exercise
input limits before parser construction, malformed central records, invalid
encoding, unusual member attributes, zero compressed-size ratios and oversized
declared integers. No unbounded fixture generation, actual bombs or offensive
third-party target. Keep failed checks and unavailable platform/scanner results.

## Worker and approval handoff

Security judgments and source verification stay in Codex. Suitable public fixture
ideas may use local Ollama first after approval; if inadequate, deliberately
choose one verified eligible free worker and preserve raw drafts. This workstream
already encountered truncated/inaccurate local drafting and an empty free
OpenRouter response; no repeated drafting attempt was needed for this security
plan. Laya's tested classification schemas do not add value here.

Next: coordinator review of this exact plan, confirmation of no overlap and a
recorded stage approval. Do not create successor code before that approval.
