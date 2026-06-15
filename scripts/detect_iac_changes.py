"""Decide whether a Sinistral scan is needed based on which files a change touched.

Runs before the scan as a fast gate: if a push/PR changed nothing under the
directories Sinistral would scan (`iac_directories`), the scan is pointless and
we skip it. The gate reads the same `iac_directories` input the scan does and is
deliberately conservative — it matches the whole subtree, so under `recurse:
false` (which scans only the top level) it may scan when a change is confined to
a subdirectory, but it never skips a file the scan would read.

Stdlib-only on purpose: the action runs this with the runner's system `python3`
*before* installing uv/Python, so a skipped run pays neither the scan nor the
toolchain setup.

Fail-open: on any uncertainty (no base to diff against, an API error, a diff too
large to read fully) we scan. We never skip unless we positively confirmed that
no Terraform file under a scanned directory changed.
"""
# Copyright (c) 2026 - Stacklet, Inc.

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# The compare API caps its `files` array at this many entries server-side; at
# the cap the list may be truncated and we can't trust a "nothing matched"
# conclusion, so we scan.
COMPARE_FILES_CAP = 300

_ZERO_SHA = "0" * 40

# File suffixes c7n_left's Terraform provider loads (HCL + JSON config and
# their variable files). A change to anything else under a scanned directory
# can't alter a scan result, so it doesn't warrant a scan. `.tfvars.json` ends
# with `.json` not `.tfvars`, and `.tf.json` not with `.tf`, so each needs its
# own entry.
TERRAFORM_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json")


def parse_directories(iac_dirs_input: str) -> list[str]:
    """Parse newline-separated directory input, filtering empty lines."""
    return [line.strip() for line in iac_dirs_input.strip().split("\n") if line.strip()]


def path_in_directory(filename: str, directory: str) -> bool:
    """Whether a repo-relative filename lives under the given directory.

    A directory of "." or "" means the whole repo, so everything matches.
    """
    norm = directory.strip().removeprefix("./").rstrip("/")
    if norm in ("", "."):
        return True
    name = filename.removeprefix("./")
    return name == norm or name.startswith(f"{norm}/")


def is_terraform_file(filename: str) -> bool:
    """Whether a changed file is one c7n_left would actually parse."""
    return filename.endswith(TERRAFORM_SUFFIXES)


def any_changed_in_directories(changed_files: list[str], directories: list[str]) -> bool:
    """Whether any changed Terraform file falls under any of the scanned directories."""
    return any(
        is_terraform_file(f) and path_in_directory(f, d) for f in changed_files for d in directories
    )


def fetch_changed_files(*, api_url: str, repo: str, base: str, head: str, token: str) -> list[str]:
    """Return the filenames changed between base and head via the compare API.

    Raises on HTTP/parse errors and on a truncated (capped) file list, so the
    caller fails open and scans rather than skipping on incomplete data.
    """
    url = f"{api_url}/repos/{repo}/compare/{base}...{head}"
    request = urllib.request.Request(url)  # noqa: S310 — url is built from trusted GHA env
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        payload = json.load(response)

    files = payload.get("files") or []
    if len(files) >= COMPARE_FILES_CAP:
        msg = f"compare returned {len(files)} files (capped at {COMPARE_FILES_CAP}); list may be truncated"
        raise RuntimeError(msg)
    return [f["filename"] for f in files]


def resolve_refs() -> tuple[str, str] | None:
    """Resolve (base, head) SHAs to diff, or None if there's nothing to compare.

    Returns None (→ fail open, scan) for events we don't understand or when no
    usable base exists (e.g. a branch's first push, where `before` is all-zeros).
    """
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    base = os.environ.get("BASE_SHA", "").strip()
    head = os.environ.get("HEAD_SHA", "").strip()

    if event not in ("pull_request", "pull_request_target", "push"):
        return None
    if not base or not head or base == _ZERO_SHA:
        return None
    return base, head


def decide() -> tuple[bool, str]:
    """Return (should_scan, human-readable reason)."""
    if os.environ.get("SKIP_UNCHANGED", "true") != "true":
        return True, "skip_unchanged disabled; scanning"

    directories = parse_directories(os.environ.get("IAC_DIRECTORIES", ""))
    if not directories:
        return True, "no iac_directories configured; scanning"

    refs = resolve_refs()
    if refs is None:
        return True, "no usable base/head to diff (or unsupported event); scanning"
    base, head = refs

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not repo:
        return True, "GITHUB_REPOSITORY unset; scanning"

    try:
        changed = fetch_changed_files(api_url=api_url, repo=repo, base=base, head=head, token=token)
    except (urllib.error.URLError, OSError, ValueError, KeyError, RuntimeError) as exc:
        return True, f"could not determine changed files ({exc}); scanning to be safe"

    dirs = ", ".join(directories)
    if any_changed_in_directories(changed, directories):
        return True, f"Terraform changes under scanned directories ({dirs}); scanning"
    return False, f"no Terraform changes under scanned directories ({dirs}); skipping scan"


def write_github_output(name: str, value: str, github_output_file: str) -> None:
    """Append a single-line output to the GitHub Actions output file."""
    with Path(github_output_file).open("a", encoding="utf-8") as f:
        f.write(f"{name}={value}\n")


def announce_skip() -> None:
    """Surface a skipped scan in the log and the Actions job summary."""
    message = "⏭️ Skipped — no Terraform changes"
    print(f"::notice::sinistral-action: {message}")
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with Path(summary_file).open("a", encoding="utf-8") as f:
            f.write(f"### Sinistral\n\n{message}\n")


def main() -> None:
    """Decide whether to scan and emit `should_scan` to the GitHub output file."""
    should_scan, reason = decide()
    print(f"detect_iac_changes: {reason}")

    # Without GITHUB_OUTPUT we can't emit should_scan; downstream steps would
    # then read an empty string and silently skip the scan (fail-closed). Fail
    # loudly instead so the failure is visible rather than a silent unscanned run.
    github_output = os.environ.get("GITHUB_OUTPUT")
    if not github_output:
        print(
            "detect_iac_changes: GITHUB_OUTPUT is not set; cannot emit should_scan", file=sys.stderr
        )
        sys.exit(1)

    write_github_output("should_scan", "true" if should_scan else "false", github_output)
    if not should_scan:
        announce_skip()


if __name__ == "__main__":
    main()
