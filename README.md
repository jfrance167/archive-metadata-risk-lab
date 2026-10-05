# Archive metadata risk lab

A Python learning tool that reports suspicious ZIP central-directory metadata
without reading, extracting or decompressing members. All supplied demos are
small inert fixtures generated in memory. A complete metadata report can contain
risk findings and never means an archive is safe to extract.

## Run

Tested locally on Windows with CPython 3.13.7. Runtime uses only the standard
library. Run these commands from this directory:

```powershell
python -m archive_lab demo
python -m unittest discover -s tests -v
```

Reusable API:

```python
from archive_lab import analyze, serialize_report
from archive_lab.fixtures import make_zip

report = analyze(make_zip(("../outside.txt",)))
print(serialize_report(report).decode("utf-8"))
```

The `analyze` CLI accepts binary bytes on stdin. For a synthetic example without
PowerShell binary-pipeline conversion, use Python to send bytes directly:

```python
import subprocess
import sys
from archive_lab.fixtures import make_zip

result = subprocess.run(
    [sys.executable, "-m", "archive_lab", "analyze"],
    input=make_zip(), capture_output=True, check=False,
)
print(result.returncode, result.stdout.decode("utf-8"))
```

Exit codes: 0 complete metadata without findings (or passing demo), 1 complete
metadata with findings (or failed demo), 2 malformed/unsupported/over-limit,
3 input/output failure. The demo's `passed` field checks expected structural
statuses; the tests separately assert findings and forbidden capabilities.

## Architecture and security model

Bounded bytes → `ZipFile(BytesIO)` → central-directory metadata → conservative
name, attribute and declared-size checks → escaped bounded JSON.

- A 64 KiB byte cap is checked **before** constructing `ZipFile`.
- The constructor parses the whole central directory. The 16-entry admission
  limit is checked afterward; it is not a preallocation limit. Larger archives
  return an incomplete result with no accepted prefix.
- Original and effective decoded names are checked independently before their
  128-character display previews are truncated. They are not raw filename bytes.
- Extra fields support empty metadata or a single supported ZIP64 record decoded
  by the standard library. Other fields, including Unicode Path overrides, are
  unsupported. Malformed framing is rejected.
- Findings cover traversal/absolute/drive names, reserved Windows names,
  controls, conservative aliases, symlink attributes, and declared sizes/ratios.
  Thresholds are 256 KiB per entry, 1 MiB total and ratio 100; these are advisory
  metadata thresholds, not measured expansion.
- Reports distinguish `complete_metadata`, `malformed`, `unsupported`, and
  `over_limit`. JSON including its newline is capped at 32 KiB; excessive output
  becomes an explicit incomplete result. Strings are escaped for terminal use.

Threats include deceptive filenames, attributes, sizes and parser inputs. There
is no member-content capability in the analyzer. Central/local-header agreement,
member content, CRC validity and extraction safety remain **unverified**.
Filesystem alias detection is conservative and incomplete. A parser vulnerability
or downstream misuse remains possible; no hard process time/RSS guarantee or
malware sandbox is claimed. This lab's authorization covers inert fixtures only.

## Verification and portfolio preparation

21 regression tests and 8 demo cases passed locally; Bandit and the workflow
policy verifier results are in `evidence/`. See [verification](docs/VERIFICATION.md)
and [ECC self-review](docs/REVIEW.md) for scope and limits. Hosted Actions and
CodeQL have not run; Windows/Ubuntu Python 3.13 workflows are prepared with reviewed
immutable action pins, minimum permissions and disabled persisted credentials.
Dependency versions are pinned; artifact hashes are not available. Install
development checks in a virtual environment using `requirements-security.txt`.
Runtime needs none of those dependencies.

This is a local repository with no publication, merge or deployment. Remote
eligibility, branch protections, dependency/secret-scanning settings and hosted
results require a separately authorized publication stage.

## Learning, sources and attribution

See [decisions](DECISIONS.md), [learning](LEARNING.md), and [approved plan](docs/PLAN.md).
Source research used [Python zipfile documentation](https://docs.python.org/3.13/library/zipfile.html),
[Microsoft filename rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file),
and inspected installed CPython 3.13.7 source. Research reviewed
[Didier Stevens' zipdump](https://github.com/DidierStevens/DidierStevensSuite/blob/master/zipdump.py)
as a broader alternative; its code was not adopted or executed. Maintenance and
issue review was incomplete. Build was preferred for this narrowly bounded lab.

Original application code is MIT licensed. CPython source excerpts retained as
review evidence remain under its accompanying [license](evidence/CPython-LICENSE.txt).
Security-workflow verification was reused from Jake's AI Tool Policy Lab.
Codex assisted research, implementation, tests and self-review. One local Ollama
draft suggested bounded test ideas; unsuitable suggestions were rejected. No
worker-generated code was executed and no remote inference was used for this lab.

## Publication status

See [publication review](PUBLICATION.md) for the October 5 source snapshot, fresh local checks, evidence boundaries and current hosted-check distinction.
