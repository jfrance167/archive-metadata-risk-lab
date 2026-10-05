# ECC self-review — October 5, 2026

Scope: all original analyzer, fixture, CLI and test code, reused workflow checker,
both workflow YAML files, security dependency pins and public documentation.
Reviewed callers, input/metadata/output boundaries and saved CPython source
excerpts using the installed ECC code-review entry point and pinned checklist.
This was the implementing Codex agent's self-review, not an independent review.
No native ECC plugin or autonomous reviewer was used.

Concrete initial regression: `test_paths_and_reserved_names` constructed its
backslash input through Windows ZipInfo, which changed that name before analysis.
The expected backslash finding was absent. Fixed by patching a same-length inert
central-directory name; removed the similarly sanitized alias fixture, preserving
case/NFC/trailing-dot/duplicate collision cases. No analyzer failure was established
by that initial test failure. Final CLI tests exercise read/write/flush/short-write
errors and ensure output-limit fallback returns incomplete status even for demos.

Final review: no unresolved actionable defects established. Security boundaries
match the approved scope: input rejected before parsing, count rejected after
whole-directory parsing, both decoded names inspected, unsupported extras excluded,
no member-content access, capped escaped reports and failed I/O exit statuses.
ZIP64 support intentionally excludes disk-start extensions and unusual shapes.
Missing content/local-header checks are explicit limits, not extraction guarantees.

| Severity | Unresolved findings |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

Verdict: approved for the authorized local synthetic lab scope. This does not
authorize merge, publication, deployment or handling real hostile archives.
21 tests, 8 demo statuses, Bandit and both normal/optimized workflow checks passed.
Parser vulnerabilities, platform/runtime differences, incomplete alias coverage,
metadata deception and unavailable hosted/secret checks remain limitations.
