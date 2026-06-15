"""Tests for detect_iac_changes.py"""
# Copyright (c) 2026 - Stacklet, Inc.

import io
import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest
from detect_iac_changes import (
    announce_skip,
    any_changed_in_directories,
    decide,
    fetch_changed_files,
    is_terraform_file,
    main,
    path_in_directory,
    resolve_refs,
)


class TestPathInDirectory:
    @pytest.mark.parametrize(
        ("filename", "directory", "expected"),
        [
            ("infra/platform/main.tf", "infra/", True),
            ("infra/platform/main.tf", "infra", True),
            ("infra/platform/main.tf", "./infra", True),
            ("./infra/platform/main.tf", "infra", True),
            ("infra", "infra", True),
            ("infra/main.tf", "infra/platform", False),
            ("infrastructure/main.tf", "infra", False),  # prefix-but-not-subpath
            ("src/stacklet/x.py", "infra", False),
            ("anything", ".", True),  # whole-repo dir
            ("anything", "", True),
        ],
        ids=[
            "subpath-trailing-slash",
            "subpath-no-slash",
            "subpath-dot-prefix",
            "filename-dot-prefix",
            "exact-match",
            "sibling-not-match",
            "prefix-not-subpath",
            "unrelated",
            "dot-matches-all",
            "empty-matches-all",
        ],
    )
    def test_path_in_directory(self, filename, directory, expected):
        assert path_in_directory(filename, directory) is expected


class TestIsTerraformFile:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("infra/main.tf", True),
            ("infra/config.tf.json", True),
            ("infra/prod.tfvars", True),
            ("infra/prod.tfvars.json", True),
            ("infra/terraform.tfvars", True),
            ("infra/x.auto.tfvars", True),
            ("infra/README.md", False),
            ("infra/deploy.py", False),
            ("infra/main.tofu", False),  # OpenTofu — c7n_left doesn't parse it
        ],
    )
    def test_is_terraform_file(self, filename, expected):
        assert is_terraform_file(filename) is expected


class TestAnyChangedInDirectories:
    def test_match(self):
        assert any_changed_in_directories(["README.md", "infra/x.tf"], ["infra/"]) is True

    def test_no_match(self):
        assert any_changed_in_directories(["README.md", "src/app.py"], ["infra/"]) is False

    def test_non_terraform_under_dir_does_not_match(self):
        """A non-Terraform file under the scanned dir can't change a scan result."""
        assert (
            any_changed_in_directories(["infra/README.md", "infra/deploy.py"], ["infra/"]) is False
        )

    def test_terraform_outside_dir_does_not_match(self):
        assert any_changed_in_directories(["docs/main.tf"], ["infra/"]) is False

    def test_multiple_directories(self):
        files = ["modules/net/main.tf"]
        assert any_changed_in_directories(files, ["infra/", "modules/"]) is True

    def test_empty_changes(self):
        assert any_changed_in_directories([], ["infra/"]) is False


class TestResolveRefs:
    def test_pull_request(self, monkeypatch):
        monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
        monkeypatch.setenv("BASE_SHA", "aaa")
        monkeypatch.setenv("HEAD_SHA", "bbb")
        assert resolve_refs() == ("aaa", "bbb")

    def test_pull_request_target(self, monkeypatch):
        monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request_target")
        monkeypatch.setenv("BASE_SHA", "aaa")
        monkeypatch.setenv("HEAD_SHA", "bbb")
        assert resolve_refs() == ("aaa", "bbb")

    def test_push(self, monkeypatch):
        monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
        monkeypatch.setenv("BASE_SHA", "aaa")
        monkeypatch.setenv("HEAD_SHA", "bbb")
        assert resolve_refs() == ("aaa", "bbb")

    def test_zero_base_returns_none(self, monkeypatch):
        """A brand-new branch's push has an all-zero `before` — no base to diff."""
        monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
        monkeypatch.setenv("BASE_SHA", "0" * 40)
        monkeypatch.setenv("HEAD_SHA", "bbb")
        assert resolve_refs() is None

    def test_missing_head_returns_none(self, monkeypatch):
        monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
        monkeypatch.setenv("BASE_SHA", "aaa")
        monkeypatch.delenv("HEAD_SHA", raising=False)
        assert resolve_refs() is None

    def test_unsupported_event_returns_none(self, monkeypatch):
        monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
        monkeypatch.setenv("BASE_SHA", "aaa")
        monkeypatch.setenv("HEAD_SHA", "bbb")
        assert resolve_refs() is None


class TestFetchChangedFiles:
    def test_returns_filenames(self):
        payload = {"files": [{"filename": "infra/a.tf"}, {"filename": "README.md"}]}
        with patch("urllib.request.urlopen", side_effect=fake_response(payload)):
            files = fetch_changed_files(
                api_url="https://api.github.com", repo="o/r", base="a", head="b", token=""
            )
        assert files == ["infra/a.tf", "README.md"]

    def test_no_files_key(self):
        with patch("urllib.request.urlopen", side_effect=fake_response({})):
            assert (
                fetch_changed_files(
                    api_url="https://api.github.com", repo="o/r", base="a", head="b", token=""
                )
                == []
            )

    def test_truncated_list_raises(self):
        """A capped file list can't prove 'nothing matched', so it must raise."""
        payload = {"files": [{"filename": f"f{i}.txt"} for i in range(300)]}
        with (
            patch("urllib.request.urlopen", side_effect=fake_response(payload)),
            pytest.raises(RuntimeError, match="truncated"),
        ):
            fetch_changed_files(
                api_url="https://api.github.com", repo="o/r", base="a", head="b", token=""
            )


class TestDecide:
    """End-to-end decision logic, with the network call stubbed."""

    def _env(self, monkeypatch, **overrides):
        defaults = {
            "IAC_DIRECTORIES": "infra/",
            "GITHUB_EVENT_NAME": "pull_request",
            "BASE_SHA": "aaa",
            "HEAD_SHA": "bbb",
            "GITHUB_REPOSITORY": "stacklet/platform",
            "GITHUB_TOKEN": "t",
        }
        defaults.update(overrides)
        for k, v in defaults.items():
            monkeypatch.setenv(k, v)

    def test_scans_when_iac_changed(self, monkeypatch):
        self._env(monkeypatch)
        with patch("detect_iac_changes.fetch_changed_files", return_value=["infra/a.tf"]):
            should_scan, _ = decide()
        assert should_scan is True

    def test_skips_when_only_non_terraform_under_dir_changed(self, monkeypatch):
        """A docs/script change inside the scanned dir must not trigger a scan."""
        self._env(monkeypatch)
        with patch("detect_iac_changes.fetch_changed_files", return_value=["infra/README.md"]):
            should_scan, reason = decide()
        assert should_scan is False
        assert "skipping" in reason

    def test_skips_when_no_iac_changed(self, monkeypatch):
        self._env(monkeypatch)
        with patch("detect_iac_changes.fetch_changed_files", return_value=["src/app.py"]):
            should_scan, reason = decide()
        assert should_scan is False
        assert "skipping" in reason

    def test_fails_open_on_api_error(self, monkeypatch):
        self._env(monkeypatch)
        with patch(
            "detect_iac_changes.fetch_changed_files",
            side_effect=urllib.error.URLError("boom"),
        ):
            should_scan, reason = decide()
        assert should_scan is True
        assert "to be safe" in reason

    def test_fails_open_when_no_directories(self, monkeypatch):
        self._env(monkeypatch, IAC_DIRECTORIES="")
        should_scan, _ = decide()
        assert should_scan is True

    def test_fails_open_on_new_branch_push(self, monkeypatch):
        self._env(monkeypatch, GITHUB_EVENT_NAME="push", BASE_SHA="0" * 40)
        should_scan, _ = decide()
        assert should_scan is True

    def test_fails_open_when_repo_unset(self, monkeypatch):
        self._env(monkeypatch)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        should_scan, _ = decide()
        assert should_scan is True

    def test_skip_unchanged_disabled_always_scans(self, monkeypatch):
        """skip_unchanged=false bypasses detection entirely (no API call)."""
        self._env(monkeypatch, SKIP_UNCHANGED="false")
        should_scan, reason = decide()
        assert should_scan is True
        assert "disabled" in reason


class TestAnnounceSkip:
    def test_notice_and_summary(self, tmp_path, monkeypatch, capsys):
        summary = tmp_path / "summary"
        summary.touch()
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

        announce_skip()

        assert "::notice::" in capsys.readouterr().out
        assert "Skipped" in summary.read_text()

    def test_no_summary_file_is_safe(self, monkeypatch, capsys):
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        announce_skip()
        assert "::notice::" in capsys.readouterr().out


class TestMain:
    """Wiring between decide(), the GITHUB_OUTPUT guard, and the output file."""

    def test_writes_should_scan_true(self, tmp_path, monkeypatch):
        github_output = tmp_path / "out"
        github_output.touch()
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        with patch("detect_iac_changes.decide", return_value=(True, "scanning")):
            main()
        assert "should_scan=true" in github_output.read_text()

    def test_writes_should_scan_false_and_announces(self, tmp_path, monkeypatch, capsys):
        github_output = tmp_path / "out"
        github_output.touch()
        summary = tmp_path / "summary"
        summary.touch()
        monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        with patch("detect_iac_changes.decide", return_value=(False, "skipping scan")):
            main()
        assert "should_scan=false" in github_output.read_text()
        assert "Skipped" in summary.read_text()
        assert "::notice::" in capsys.readouterr().out

    def test_exits_when_github_output_unset(self, monkeypatch):
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        with (
            patch("detect_iac_changes.decide", return_value=(True, "scanning")),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        assert exc.value.code == 1


def fake_response(payload):
    """A urlopen() side_effect that yields a fresh one-shot stream on each call.

    `io.BytesIO` is consumed by `json.load`, so a single instance can't serve a
    retry or a second call; returning a callable rebuilds it per invocation.
    """

    def _make(*_args, **_kwargs):
        cm = MagicMock()
        cm.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
        cm.__exit__.return_value = False
        return cm

    return _make
