# Verification — October 5, 2026

Actual environment: Windows, CPython 3.13.7 (record and source hashes in
`evidence/runtime.json`). Recorded inspected CPython code retains original names,
sanitizes effective names, permits Unicode Path overrides and parses the complete
central directory before `infolist()` is available. License retained beside excerpts.

| Check | Actual result |
|---|---|
| `python -m unittest discover -s tests -v` | 21 methods passed |
| `python -m archive_lab demo` | 8 expected structural statuses; passed |
| `python -m bandit -r archive_lab tools -f json -o evidence/bandit.json` | Exit 0; no findings/errors/suppressions |
| `python tools/verify_workflows.py` | PASS |
| `python -O tools/verify_workflows.py` | PASS; verification survives disabled asserts |
| `python -m pip check` | No broken requirements in installed environment |

Evidence: `tests.txt`, `demo.json`, `bandit.json`, `workflow-policy*.json`,
`pip-check.txt`, `check-exits.json` under `evidence/`. First 16-method test run
had one backslash fixture failure; its cause and correction are in LEARNING.md.

Forbidden-capability regressions patch ZipFile member open/read/extract/extractall/
testzip, decompressor entry points and builtin file opening while running synthetic
metadata scenarios. Fixtures are constructed beforehand because writing a fixture
legitimately uses ZipFile.open internally. No hostile payloads were executed.

Action SHAs were reused from the prior lab's verified official-source mapping:
checkout v7.0.1, setup-python v7.0.0 and CodeQL v4.38.2. The workflow utility checks
their exact values, triggers, permissions and credential setting. It does not
prove remote availability, action internals or successful hosted execution.

Only this installed runtime/platform was exercised. Hosted Windows/Ubuntu Python
3.13 CI and CodeQL are prepared but unrun. Dependency pins have no artifact hashes;
previous PyPI metadata attempts failed with TLS resets, so no lock integrity claim.
A dedicated secret scanner is unavailable; bounded credential/private-path checks
and manual review cannot establish absence of every secret. No remote repository,
security alert inventory or protection eligibility was available to inspect.

ECC self-review is recorded separately. Passing checks do not prove extraction
safety or a general vulnerability-free parser/application.
