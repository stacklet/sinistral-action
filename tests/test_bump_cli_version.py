"""Tests for the sinistral-cli version bump script."""
# Copyright (c) 2026 - Stacklet, Inc.

import pytest
from bump_cli_version import (
    Pin,
    apply,
    describe,
    find_tag,
    pin_line_index,
    read_doc,
    read_pin,
    resolve,
    write_doc,
    write_pin,
)

SHA = "dbefcee8c50ad4300be1236e10dc613bd9c2f3dc"
OLD_SHA = "8552c68f72b9df5bb4985f722fec4063ebb35218"

ACTION_YML = """\
inputs:
  sinistral_project:
    required: true
    description: Sinistral project name to scan against
  sinistral_cli_version:
    required: false
    description: >
      sinistral-cli version to use. Accepts any git ref (branch, tag, SHA) from
      https://github.com/stacklet/sinistral-cli.
    default: '{value}'{comment}
  post_pr_comment:
    required: false
    default: 'true'
"""

README = """\
| Input | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `recurse` | No | `false` | Recursively discover subdirectories. |
| `sinistral_cli_version` | No | `{value}` | Git ref (tag, branch, SHA) of sinistral-cli. |
| `post_pr_comment` | No | `true` | Whether to post scan results as a PR comment. |
"""


def action_yml(value: str, comment: str | None = None) -> str:
    return ACTION_YML.format(value=value, comment=f" # {comment}" if comment else "")


def readme(value: str) -> str:
    return README.format(value=value)


class TestPinLineIndex:
    def test_finds_default_within_the_block(self):
        lines = action_yml(SHA, "v0.5.38").splitlines()
        index = pin_line_index(lines)
        assert index is not None
        assert lines[index].strip().startswith("default:")

    def test_skips_defaults_of_other_inputs(self):
        # The first `default:` in the file belongs to a later input; picking it
        # would rewrite post_pr_comment instead.
        lines = action_yml(SHA, "v0.5.38").splitlines()
        index = pin_line_index(lines)
        assert index is not None
        assert lines[index].endswith("' # v0.5.38")

    def test_missing_input_returns_none(self):
        assert pin_line_index(["inputs:", "  other:", "    default: 'x'"]) is None

    def test_block_without_default_returns_none(self):
        lines = [
            "inputs:",
            "  sinistral_cli_version:",
            "    required: false",
            "  post_pr_comment:",
            "    default: 'true'",
        ]
        assert pin_line_index(lines) is None


class TestReadPin:
    def test_reads_sha_and_comment(self):
        assert read_pin(action_yml(SHA, "v0.5.38")) == Pin(SHA, "v0.5.38")

    def test_reads_pin_without_a_comment(self):
        assert read_pin(action_yml("v0.5.34")) == Pin("v0.5.34", "")

    def test_reads_a_comment_containing_spaces(self):
        pinned = action_yml(SHA, "demo-fixes (2023-03-13)")
        assert read_pin(pinned) == Pin(SHA, "demo-fixes (2023-03-13)")

    def test_missing_input_returns_none(self):
        assert read_pin("inputs:\n  other:\n    default: 'x'\n") is None


class TestWritePin:
    def test_replaces_the_sha_and_comment(self):
        result = write_pin(action_yml(OLD_SHA, "v0.5.36"), Pin(SHA, "v0.5.38"))
        assert f"    default: '{SHA}' # v0.5.38\n" in result
        assert OLD_SHA not in result

    def test_upgrades_a_bare_tag_pin(self):
        result = write_pin(action_yml("v0.5.34"), Pin(SHA, "v0.5.38"))
        assert f"    default: '{SHA}' # v0.5.38\n" in result

    def test_leaves_other_inputs_alone(self):
        result = write_pin(action_yml(OLD_SHA, "v0.5.36"), Pin(SHA, "v0.5.38"))
        assert "    default: 'true'\n" in result
        assert result.count("default:") == action_yml("x", "c").count("default:")

    def test_round_trips_through_read_pin(self):
        pin = Pin(SHA, "demo-fixes (2023-03-13)")
        assert read_pin(write_pin(action_yml("v0.5.34"), pin)) == pin

    def test_preserves_surrounding_content(self):
        result = write_pin(action_yml(OLD_SHA, "v0.5.36"), Pin(SHA, "v0.5.38"))
        assert result.startswith("inputs:\n  sinistral_project:\n")
        assert result.endswith("    default: 'true'\n")

    @pytest.mark.parametrize("name", ["v1.0&2", r"back\slash", "at@sign", "semi;colon"])
    def test_names_with_replacement_metacharacters(self, name):
        # These characters are special to sed's replacement side; the point of
        # the Python rewrite is that they need no escaping.
        assert read_pin(write_pin(action_yml("v0.5.34"), Pin(SHA, name))) == Pin(SHA, name)

    def test_missing_input_exits(self):
        with pytest.raises(SystemExit):
            write_pin("inputs:\n  other:\n    default: 'x'\n", Pin(SHA, "v0.5.38"))


class TestReadme:
    def test_reads_the_documented_default(self):
        assert read_doc(readme("v0.5.34")) == "v0.5.34"

    def test_writes_the_documented_default(self):
        assert read_doc(write_doc(readme("v0.5.34"), "v0.5.38")) == "v0.5.38"

    def test_leaves_other_rows_alone(self):
        result = write_doc(readme("v0.5.34"), "v0.5.38")
        assert "| `recurse` | No | `false` |" in result
        assert "| `post_pr_comment` | No | `true` |" in result

    @pytest.mark.parametrize("name", ["v1.0&2", r"back\slash", "at@sign"])
    def test_names_with_replacement_metacharacters(self, name):
        assert read_doc(write_doc(readme("v0.5.34"), name)) == name

    def test_missing_row_returns_none(self):
        assert read_doc("| Input | Required |\n| `other` | No | `x` |\n") is None

    def test_missing_row_exits_rather_than_substituting_nothing(self):
        with pytest.raises(SystemExit):
            write_doc("| Input | Required |\n| `other` | No | `x` |\n", "v0.5.38")

    def test_reformatted_row_exits(self):
        # An extra space in the Required column stops the row from matching;
        # reporting it as updated would leave the documented default stale.
        with pytest.raises(SystemExit):
            write_doc("| `sinistral_cli_version` |  No  | `v0.5.34` | desc |\n", "v0.5.38")


class TestDescribe:
    def test_prefers_a_tag_on_the_commit(self):
        assert describe("main", SHA, "2026-09-01", "v0.5.38") == "v0.5.38"

    def test_untagged_ref_gets_the_ref_and_date(self):
        assert describe("demo-fixes", SHA, "2023-03-13", None) == "demo-fixes (2023-03-13)"

    def test_untagged_full_sha_gets_a_short_sha(self):
        assert describe(SHA, SHA, "2023-03-13", None) == "dbefcee (2023-03-13)"

    def test_untagged_short_sha_gets_a_short_sha(self):
        assert describe(SHA[:8], SHA, "2023-03-13", None) == "dbefcee (2023-03-13)"


class FakeApi:
    """Stand in for gh_api, recording the paths requested."""

    def __init__(
        self, *, tag_pages=None, latest="v0.5.38", commit_sha=SHA, date="2026-09-01T12:00:00Z"
    ):
        self.pages = tag_pages if tag_pages is not None else [[]]
        self.latest = latest
        self.commit_sha = commit_sha
        self.date = date
        self.calls = []

    def __call__(self, path):
        self.calls.append(path)
        if path.endswith("/releases/latest"):
            return {"tag_name": self.latest}
        if "/commits/" in path:
            return {"sha": self.commit_sha, "commit": {"committer": {"date": self.date}}}
        page = int(path.rsplit("page=", 1)[1])
        return self.pages[page - 1] if page <= len(self.pages) else []


def tag_page(*entries):
    return [{"name": name, "commit": {"sha": sha}} for name, sha in entries]


class TestFindTag:
    def test_finds_a_tag_on_the_first_page(self):
        api = FakeApi(tag_pages=[tag_page(("v0.5.37", OLD_SHA), ("v0.5.38", SHA))])
        assert find_tag("owner/repo", SHA, api=api) == "v0.5.38"

    def test_returns_none_when_no_tag_matches(self):
        api = FakeApi(tag_pages=[tag_page(("v0.5.37", OLD_SHA))])
        assert find_tag("owner/repo", SHA, api=api) is None

    def test_stops_paging_on_a_short_page(self):
        api = FakeApi(tag_pages=[tag_page(("v0.5.37", OLD_SHA))])
        find_tag("owner/repo", SHA, api=api)
        assert len(api.calls) == 1

    def test_pages_past_a_full_page(self):
        full = tag_page(*[(f"v0.0.{n}", f"{n:040d}") for n in range(100)])
        api = FakeApi(tag_pages=[full, tag_page(("v0.5.38", SHA))])
        assert find_tag("owner/repo", SHA, api=api) == "v0.5.38"
        assert len(api.calls) == 2


class TestResolve:
    def test_latest_resolves_through_the_release(self):
        api = FakeApi(tag_pages=[tag_page(("v0.5.38", SHA))])
        assert resolve("owner/repo", "latest", api=api) == Pin(SHA, "v0.5.38")
        assert api.calls[0].endswith("/releases/latest")
        assert "/commits/v0.5.38" in api.calls[1]

    def test_explicit_ref_skips_the_release_lookup(self):
        api = FakeApi(tag_pages=[tag_page(("v0.5.36", SHA))])
        assert resolve("owner/repo", "v0.5.36", api=api) == Pin(SHA, "v0.5.36")
        assert not any("releases" in call for call in api.calls)

    def test_untagged_branch_falls_back_to_ref_and_date(self):
        api = FakeApi(tag_pages=[[]], date="2023-03-13T09:00:00Z")
        assert resolve("owner/repo", "demo-fixes", api=api) == Pin(SHA, "demo-fixes (2023-03-13)")


class TestApply:
    @pytest.fixture(autouse=True)
    def _files(self, tmp_path, monkeypatch):
        action = tmp_path / "action.yml"
        readme_file = tmp_path / "README.md"
        monkeypatch.setattr("bump_cli_version.ACTION_FILE", action)
        monkeypatch.setattr("bump_cli_version.README_FILE", readme_file)
        self.action = action
        self.readme = readme_file

    def write(self, sha, comment, readme_value):
        self.action.write_text(action_yml(sha, comment), encoding="utf-8")
        self.readme.write_text(readme(readme_value), encoding="utf-8")

    def test_both_stale(self):
        self.write(OLD_SHA, "v0.5.36", "v0.5.34")
        assert apply(Pin(SHA, "v0.5.38")) == ["action.yml", "README.md"]

    def test_both_current(self):
        self.write(SHA, "v0.5.38", "v0.5.38")
        assert apply(Pin(SHA, "v0.5.38")) == []

    def test_only_readme_stale(self):
        self.write(SHA, "v0.5.38", "v0.5.34")
        assert apply(Pin(SHA, "v0.5.38")) == ["README.md"]
        assert read_doc(self.readme.read_text(encoding="utf-8")) == "v0.5.38"

    def test_only_action_stale(self):
        self.write(OLD_SHA, "v0.5.36", "v0.5.38")
        assert apply(Pin(SHA, "v0.5.38")) == ["action.yml"]
        assert read_pin(self.action.read_text(encoding="utf-8")) == Pin(SHA, "v0.5.38")

    def test_same_commit_with_a_new_name_refreshes_the_comment(self):
        self.write(SHA, "demo-fixes (2023-03-13)", "demo-fixes (2023-03-13)")
        assert apply(Pin(SHA, "dbefcee (2023-03-13)")) == ["action.yml", "README.md"]

    def test_unwritable_file_exits_without_claiming_success(self, monkeypatch):
        # A failed write must never be reported as a completed pin. Denying the
        # write directly rather than via chmod keeps this meaningful as root,
        # who is not stopped by a read-only mode bit.
        self.write(OLD_SHA, "v0.5.36", "v0.5.34")

        def deny(*args, **kwargs):
            raise OSError(13, "Permission denied")

        monkeypatch.setattr("pathlib.Path.write_text", deny)
        with pytest.raises(SystemExit):
            apply(Pin(SHA, "v0.5.38"))
        assert read_pin(self.action.read_text(encoding="utf-8")) == Pin(OLD_SHA, "v0.5.36")

    def test_missing_readme_row_exits_without_claiming_an_update(self):
        self.write(OLD_SHA, "v0.5.36", "v0.5.34")
        self.readme.write_text("| Input | Required |\n| `other` | No | `x` |\n", encoding="utf-8")
        with pytest.raises(SystemExit):
            apply(Pin(SHA, "v0.5.38"))

    def test_missing_file_exits(self):
        self.write(OLD_SHA, "v0.5.36", "v0.5.34")
        self.action.unlink()
        with pytest.raises(SystemExit):
            apply(Pin(SHA, "v0.5.38"))

    def test_preserves_file_permissions(self):
        self.write(OLD_SHA, "v0.5.36", "v0.5.34")
        self.action.chmod(0o644)
        mode = self.action.stat().st_mode
        apply(Pin(SHA, "v0.5.38"))
        assert self.action.stat().st_mode == mode
