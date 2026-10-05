"""Check local workflow policy without claiming remote Actions execution.

Usage: python tools/verify_workflows.py [--root PROJECT_DIRECTORY]
Requires PyYAML from requirements-security.txt. Reports JSON to stdout; exits
nonzero for invalid YAML, triggers, permissions or action pins. Network-free.
Release-to-commit verification remains a separate official-source review.
"""

import argparse
import json
from pathlib import Path
import re

import yaml

PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "github/codeql-action/init": "2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
    "github/codeql-action/analyze": "2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
}


def require(condition: bool, message: str) -> None:
    """Fail explicitly rather than relying on assertions disabled by python -O."""
    if not condition:
        raise ValueError(message)


def verify(root: Path) -> dict:
    """Check this lab's expected files and fixed security configuration."""
    for name in ("checks.yml", "codeql.yml"):
        # The workflows quote `on` to preserve its spelling under YAML 1.1.
        # safe_load rejects arbitrary Python object tags in changed workflows.
        workflow = yaml.safe_load((root / ".github/workflows" / name).read_text(encoding="utf-8"))
        require(workflow["permissions"] == {"contents": "read"}, "invalid top-level permissions")
        require(set(workflow["on"]) >= {"push", "pull_request", "workflow_dispatch"}, "missing triggers")
        for event in ("push", "pull_request"):
            require(workflow["on"][event]["branches"] == ["main"], "unexpected branch scope")
        for job in workflow["jobs"].values():
            require(job.get("permissions", {"contents": "read"}) in (
                {"contents": "read"}, {"contents": "read", "actions": "read", "security-events": "write"}
            ), "excessive job permissions")
            for step in job["steps"]:
                if "uses" not in step:
                    continue
                action, sha = step["uses"].split("@")
                require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and PINS.get(action) == sha,
                        "unverified action commit")
                if action == "actions/checkout":
                    require(step["with"]["persist-credentials"] is False, "persisted checkout credentials")
        if name == "codeql.yml":
            require(workflow["on"].get("schedule") == [{"cron": "23 7 * * 1"}], "missing weekly CodeQL")
    return {"status": "PASS", "scope": "local YAML syntax, triggers, permissions and reviewed action pins",
            "remote_actions_run": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(verify(args.root), indent=2))


if __name__ == "__main__":
    main()
