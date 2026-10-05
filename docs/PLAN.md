# Approved archive metadata plan

Research/candidate/source assessment: RESEARCH.md (historical proposal; approval below supersedes its pending status),
reviewed October 5, 2026. Coordinator approved stages 1–3 under Jake's expanded
overnight mandate, with the source-grounded addendum below recorded BEFORE code.
Distinct from AI policy, pickle, TLS and firewall workstreams. Sole writer here.

Success: bounded inert ZIP bytes yield an explicit metadata-only result and
bounded escaped JSON; no member content access or extraction can occur.

Stages: (1) reusable metadata core, (2) synthetic fixture regressions and CLI,
(3) ECC self-review, affected checks, evidence, README/threat model/license/AI
disclosure, state/decisions/learning and local security-baseline preparations.

## Required source-grounded addendum

- Enforce a 64 KiB raw-input cap before ZipFile construction. The constructor
  parses the full central directory. More than 16 entries produces an explicit
  over-limit/incomplete result, never a prefix accepted as complete. No hard
  process RSS or time guarantee is claimed.
- Inspect decoded orig_filename and effective filename independently. They are
  not raw ZIP filename bytes. NUL/control/path aliases need regressions.
- Supported extra scope: empty or well-formed ZIP64 handled by stdlib. Reject
  all other extras, especially Unicode Path 0x7075, before a no-findings outcome.
  Do not introduce a new filename-decoding parser. Record interpreter source
  behavior/version; support differences remain a test/review concern.
- No ZipFile member read/open/extract/testzip or decompressor use. Declared
  sizes/ratios are untrusted metadata indicators. Central/local-header agreement,
  CRC/content validity and downstream extraction behavior remain unverified.
  There is no safe-to-extract verdict.
- Distinguish malformed, unsupported, over-limit and complete metadata results.
  Bound final JSON bytes; output write errors must produce a failed exit status.
- Use only small inert synthetic fixtures, including Unicode extras, NUL/control,
  normalized aliases and >16-entry cases. Forbidden-call tests and source review
  support capability claims. No real bombs, hostile samples or external targets.

Architecture: bounded stdin bytes -> ZipFile(BytesIO) -> metadata/extra checks ->
conservative name/attribute/declared-size rules -> bounded JSON. Runtime uses the
standard library. No payload reading, network, plugins/passwords or extraction.
Initial metadata thresholds: 256 KiB declared per entry, 1 MiB total, ratio 100.

Threats: hostile names, attributes, declarations and parser inputs. Controls:
raw input/report bounds, explicit supported scope, no dangerous member capability,
escaped strings and fail-closed parse errors. Limits: parser vulnerabilities,
Unicode aliases, deceptive metadata and downstream misuse. This host exercise
is not a malware sandbox; real samples require separately approved isolation.

Verification: prove size rejection before parser; all-entry count rejection;
original/effective name handling; malformed/unsupported extra records; sizes,
ratios, encryption and compression methods; deterministic safe reports; output
limits/write errors; zero member reads/decompression. Preserve failed evidence
and unavailable platforms/scanners; manual review precedes merge/deployment.

