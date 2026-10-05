"""Read bounded synthetic ZIP bytes from stdin or run a deterministic demo."""

import argparse
import json
import sys

from .analyzer import MAX_INPUT_BYTES, analyze, serialize_report
from .fixtures import demo_cases


def main() -> int:
    parser = argparse.ArgumentParser(description="ZIP metadata risk lab; never extracts members")
    parser.add_argument("command", choices=("analyze", "demo"))
    args = parser.parse_args()
    try:
        if args.command == "analyze":
            report = analyze(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        else:
            cases = [{"case": name, "expected_status": expected, "report": analyze(raw)}
                     for name, raw, expected in demo_cases()]
            report = {"mode": "inert_synthetic_metadata", "cases": cases,
                      "passed": all(case["report"]["status"] == case["expected_status"] for case in cases)}
        payload = serialize_report(report)
        emitted = json.loads(payload)
        written = sys.stdout.buffer.write(payload)
        if written != len(payload):
            raise OSError("short output write")
        sys.stdout.buffer.flush()
    except OSError:
        # Prevent a second failed stdout flush at interpreter shutdown. No file
        # is opened to redirect output; failure remains a nonzero CLI result.
        sys.stdout = None
        try:
            print('{"error":"input_or_output_failure"}', file=sys.stderr)
        except OSError:
            pass
        return 3
    if emitted.get("status") == "over_limit":
        return 2
    if args.command == "demo":
        return 0 if report["passed"] else 1
    if report["status"] != "complete_metadata":
        return 2
    return 1 if any(entry["findings"] for entry in report["entries"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
