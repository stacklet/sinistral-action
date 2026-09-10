"""Repoint the action's default sinistral-cli version at a resolved commit.

`action.yml` pins `sinistral_cli_version` to a full commit SHA so a run can't be
retargeted by moving a tag, with a trailing comment carrying the human-readable
version so the pin stays reviewable. This keeps both halves of that pattern —
and the copy of the default documented in the README table — in step.

Any git ref works: a tag, a branch, or a full or short SHA. The comment prefers
a tag pointing at the resolved commit; failing that it records what was asked
for, dated, so it still says something the SHA doesn't.

A maintenance script, not part of the action itself: it runs on a developer's
machine via `just bump-cli-version`, and reaches GitHub through the `gh` CLI so
it inherits an existing login rather than needing a token of its own.
"""
# Copyright (c) 2026 - Stacklet, Inc.

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple, NoReturn

# Decoded JSON from the GitHub API: an object or an array, shaped by whichever
# endpoint produced it.
type Json = Any

DESCRIPTION = "Repoint the action's default sinistral-cli version at a resolved commit."
DEFAULT_REPO = "stacklet/sinistral-cli"
INPUT_NAME = "sinistral_cli_version"

ROOT = Path(__file__).resolve().parent.parent
ACTION_FILE = ROOT / "action.yml"
README_FILE = ROOT / "README.md"

# The pinned line inside the input's block, e.g.
#     default: 'dbefcee...' # v0.5.38
# The comment is optional: an older pin may be a bare tag with nothing after it.
PIN_LINE = re.compile(r"^(?P<indent>\s*)default: '(?P<sha>[^']*)'(?:\s*#\s*(?P<name>.*?))?\s*$")

# The input's row in the README table, whose Default column repeats the version.
README_ROW = re.compile(rf"^(\| `{INPUT_NAME}` \| No \| `)(?P<name>[^`]*)(`)", re.MULTILINE)

# Guard against paging forever if the tags endpoint ever misbehaves.
TAG_PAGE_SIZE = 100
MAX_TAG_PAGES = 20


class Pin(NamedTuple):
    """A resolved commit and the human-readable name recorded alongside it."""

    sha: str
    name: str


def fail(message: str) -> NoReturn:
    """Report an error and exit non-zero."""
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def gh_path() -> str:
    """Locate the `gh` CLI, with install guidance if it isn't on PATH."""
    found = shutil.which("gh")
    if found is None:
        fail("'gh' not found. Install the GitHub CLI and run `gh auth login`.")
    return found


def gh_api(path: str) -> Json:
    """Fetch a GitHub API path through the `gh` CLI and parse the JSON response."""
    try:
        result = subprocess.run(
            [gh_path(), "api", path],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        fail(error.stderr.strip() or f"gh api {path} failed")
    return json.loads(result.stdout)


def find_tag(repo: str, sha: str, *, api: Callable[[str], Json] = gh_api) -> str | None:
    """Return the first tag pointing at the given commit, or None if it has none."""
    for page in range(1, MAX_TAG_PAGES + 1):
        tags = api(f"repos/{repo}/tags?per_page={TAG_PAGE_SIZE}&page={page}")
        for tag in tags:
            if tag["commit"]["sha"] == sha:
                return str(tag["name"])
        if len(tags) < TAG_PAGE_SIZE:
            break
    return None


def describe(ref: str, sha: str, date: str, tag: str | None) -> str:
    """Name a commit for the pin comment.

    A tag on the commit is the most useful label. Without one, the ref that was
    asked for plus the commit date beats repeating the SHA — except when the ref
    *is* the SHA, where a short SHA and the date are all there is to say.
    """
    if tag:
        return tag
    label = sha[:7] if sha.startswith(ref) else ref
    return f"{label} ({date})"


def resolve(repo: str, ref: str, *, api: Callable[[str], Json] = gh_api) -> Pin:
    """Resolve any git ref (or "latest") to a commit SHA and a name for it."""
    if ref == "latest":
        ref = api(f"repos/{repo}/releases/latest")["tag_name"]
    commit = api(f"repos/{repo}/commits/{ref}")
    sha = commit["sha"]
    date = commit["commit"]["committer"]["date"].split("T")[0]
    return Pin(sha, describe(ref, sha, date, find_tag(repo, sha, api=api)))


def pin_line_index(lines: list[str]) -> int | None:
    """Index of the `default:` line within the version input's block."""
    in_block = False
    for index, line in enumerate(lines):
        if line.startswith(f"  {INPUT_NAME}:"):
            in_block = True
        elif in_block:
            if line.startswith("    default:"):
                return index
            # A sibling key at the inputs level, or any dedent past it, means
            # the block ended without a default.
            if line.strip() and not line.startswith("   "):
                break
    return None


def read_pin(text: str) -> Pin | None:
    """Read the commit and comment currently pinned in action.yml."""
    lines = text.splitlines()
    index = pin_line_index(lines)
    if index is None:
        return None
    match = PIN_LINE.match(lines[index])
    if match is None:
        return None
    return Pin(match["sha"], match["name"] or "")


def write_pin(text: str, pin: Pin) -> str:
    """Return action.yml text with the input's default repointed at the pin."""
    lines = text.splitlines()
    index = pin_line_index(lines)
    if index is None:
        fail(f"no `default:` found for `{INPUT_NAME}` in {ACTION_FILE.name}")
    match = PIN_LINE.match(lines[index])
    indent = match["indent"] if match else "    "
    lines[index] = f"{indent}default: '{pin.sha}' # {pin.name}"
    return "".join(f"{line}\n" for line in lines)


def read_doc(text: str) -> str | None:
    """Read the version documented in the README's inputs table."""
    match = README_ROW.search(text)
    return match["name"] if match else None


def write_doc(text: str, name: str) -> str:
    """Return README text with the input's documented default set to name.

    A row that no longer matches would substitute nothing, and a silent no-op
    here would be reported as an updated file, so this fails like write_pin
    does when the pin has nowhere to go.
    """
    updated, count = README_ROW.subn(lambda match: f"{match[1]}{name}{match[3]}", text, count=1)
    if not count:
        fail(f"no `{INPUT_NAME}` row found in {README_FILE.name}")
    return updated


def read_file(path: Path) -> str:
    """Read a file, reporting a clean error rather than a traceback."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"could not read {path.name}: {error.strerror}")


def write_file(path: Path, text: str) -> None:
    """Write a file, reporting a clean error rather than a traceback.

    A failed write must never be mistaken for a successful pin, so this exits
    instead of returning and letting the caller report what it meant to do.
    """
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as error:
        fail(f"could not write {path.name}: {error.strerror}")


def apply(pin: Pin) -> list[str]:
    """Write the pin to every file that is out of step, returning their names.

    Each file is checked on its own: either can be stale while the other is
    current, so neither is skipped on account of the other.
    """
    changed = []

    action_text = read_file(ACTION_FILE)
    if read_pin(action_text) != pin:
        write_file(ACTION_FILE, write_pin(action_text, pin))
        changed.append(ACTION_FILE.name)

    readme_text = read_file(README_FILE)
    if read_doc(readme_text) != pin.name:
        write_file(README_FILE, write_doc(readme_text, pin.name))
        changed.append(README_FILE.name)

    return changed


def main() -> None:
    """Resolve the requested ref and update the pin wherever it is recorded."""
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        "ref",
        nargs="?",
        default="latest",
        help="git ref to pin: a tag, branch, or SHA (default: the latest release)",
    )
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help=f"repository to resolve the ref against (default: {DEFAULT_REPO})",
    )
    args = parser.parse_args()

    pin = resolve(args.repo, args.ref)
    changed = apply(pin)
    if changed:
        print(f"Pinned to {pin.sha} # {pin.name}")
        print(f"updated: {' '.join(changed)}")
    else:
        print(
            f"Already pinned to {pin.sha} # {pin.name}; "
            f"{ACTION_FILE.name} and {README_FILE.name} both current"
        )


if __name__ == "__main__":
    main()
