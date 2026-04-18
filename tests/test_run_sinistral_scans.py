"""Tests for run_sinistral_scans.py"""
# Copyright (c) 2026 - Stacklet, Inc.

# Import functions from the script
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from run_sinistral_scans import (
    aggregate_stats,
    analyze_scan_results,
    build_aggregate_summary,
    build_detail_section,
    build_summary_text,
    extract_eval_results,
    find_terraform_directories,
    format_results,
    main,
    parse_directories,
    run_all_scans,
    run_sinistral_scan,
    safe_code_block,
    update_overall_status,
    write_github_multiline_output,
    write_github_output,
)


class TestParseDirectories:
    """Test directory parsing logic."""

    def test_single_directory(self):
        """Test parsing a single directory."""
        result = parse_directories("terraform")
        assert result == ["terraform"]

    def test_multiple_directories(self):
        """Test parsing multiple newline-separated directories."""
        input_str = "terraform/prod\nterraform/staging\ninfrastructure"
        result = parse_directories(input_str)
        assert result == ["terraform/prod", "terraform/staging", "infrastructure"]

    def test_directories_with_whitespace(self):
        """Test that leading/trailing whitespace is stripped."""
        input_str = "  terraform/prod  \n  terraform/staging  "
        result = parse_directories(input_str)
        assert result == ["terraform/prod", "terraform/staging"]

    def test_empty_lines_filtered(self):
        """Test that empty lines are filtered out."""
        input_str = "terraform/prod\n\nterraform/staging\n  \ninfrastructure"
        result = parse_directories(input_str)
        assert result == ["terraform/prod", "terraform/staging", "infrastructure"]

    def test_empty_input(self):
        """Test that empty input returns empty list."""
        result = parse_directories("")
        assert result == []

    def test_whitespace_only_input(self):
        """Test that whitespace-only input returns empty list."""
        result = parse_directories("  \n  \n  ")
        assert result == []


class TestRunSinistralScan:
    """Test that run_sinistral_scan passes project and cli_version correctly."""

    def test_project_and_cli_version_in_command(self, tmp_path):
        """Test that --project and cli_version are passed to the sinistral command."""
        output_file = tmp_path / "output.txt"

        captured_cmd = []

        def fake_popen(cmd, **kwargs):
            captured_cmd.extend(cmd)
            mock = MagicMock()
            mock.stdout = iter([])
            mock.returncode = 0
            return mock

        with patch("run_sinistral_scans.subprocess.Popen", side_effect=fake_popen):
            run_sinistral_scan("terraform", output_file, project="AcmeCorp", cli_version="v0.5.34")

        assert "--project" in captured_cmd
        assert "AcmeCorp" in captured_cmd
        assert any("v0.5.34" in arg for arg in captured_cmd)

    def test_timeout_returns_error(self, tmp_path):
        """Test that a timed-out scan returns exit code 1."""
        output_file = tmp_path / "output.txt"

        def fake_popen(cmd, **kwargs):
            mock = MagicMock()
            mock.stdout = iter([])
            mock.wait = MagicMock(
                side_effect=[subprocess.TimeoutExpired(cmd="sinistral", timeout=600), None]
            )
            mock.kill = MagicMock()
            return mock

        with patch("run_sinistral_scans.subprocess.Popen", side_effect=fake_popen):
            exit_code = run_sinistral_scan(
                "terraform", output_file, project="Test", cli_version="main"
            )

        assert exit_code == 1
        content = output_file.read_text()
        assert "timed out" in content.lower()

    def test_command_not_found(self, tmp_path):
        """Test that FileNotFoundError is handled gracefully."""
        output_file = tmp_path / "output.txt"

        with patch(
            "run_sinistral_scans.subprocess.Popen", side_effect=FileNotFoundError("No such file")
        ):
            exit_code = run_sinistral_scan(
                "terraform", output_file, project="Test", cli_version="main"
            )

        assert exit_code == 1
        content = output_file.read_text()
        assert "ERROR" in content
        assert "not found" in content.lower()

    def test_default_cli_version_in_command(self, tmp_path):
        """Test that cli_version is substituted into the uvx --from URL."""
        output_file = tmp_path / "output.txt"

        captured_cmd = []

        def fake_popen(cmd, **kwargs):
            captured_cmd.extend(cmd)
            mock = MagicMock()
            mock.stdout = iter([])
            mock.returncode = 0
            return mock

        with patch("run_sinistral_scans.subprocess.Popen", side_effect=fake_popen):
            run_sinistral_scan("terraform", output_file, project="MyProject", cli_version="main")

        from_arg = next((arg for arg in captured_cmd if "sinistral-cli@" in arg), None)
        assert from_arg is not None
        assert from_arg.endswith("@main")


class TestAnalyzeScanResults:
    """Test scan result analysis logic."""

    def test_passed_no_issues(self, tmp_path):
        """Test analysis of a successful scan with no issues."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text(
            "Evaluation complete 0.01 seconds -> Success\n"
            "56 compliant of 423 total, 367 resources unevaluated\n"
        )

        status, exit_code, stats = analyze_scan_results(temp_file, 0)
        assert status == "✅ Passed"
        assert exit_code == 0
        assert stats["compliant"] == 56
        assert stats["total"] == 423
        assert stats["violating_policies"] == 0
        assert stats["unevaluated"] == 367

    def test_failed_with_violations(self, tmp_path):
        """Test analysis of a failed scan with policy violations."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text(
            "Evaluation complete 0.02 seconds -> Failure\n"
            "40 compliant of 100 total, 45 resources have 12 policy violations, 15 resources unevaluated\n"
        )

        status, exit_code, stats = analyze_scan_results(temp_file, 1)
        assert status == "❌ Failed"
        assert exit_code == 1
        assert stats["compliant"] == 40
        assert stats["total"] == 100
        assert stats["violating_resources"] == 45
        assert stats["violating_policies"] == 12
        assert stats["unevaluated"] == 15

    def test_passed_with_traceback(self, tmp_path):
        """Test analysis of a scan that passed but had warnings (traceback)."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text(
            "Some output\n"
            "Traceback (most recent call last):\n"
            "  Some warning\n"
            "Evaluation complete 0.01 seconds -> Success\n"
            "50 compliant of 100 total, 50 resources unevaluated\n"
        )

        status, exit_code, stats = analyze_scan_results(temp_file, 0)
        assert status == "⚠️ Passed with errors; incomplete scan"
        assert exit_code == 0
        assert stats["compliant"] == 50
        assert stats["total"] == 100
        assert stats["violating_policies"] == 0
        assert stats["unevaluated"] == 50

    def test_failed_with_traceback(self, tmp_path):
        """Test analysis of a scan that failed with both traceback and failure."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text(
            "Traceback (most recent call last):\n"
            "  Some error\n"
            "Evaluation complete 0.02 seconds -> Failure\n"
            "30 compliant of 100 total, 60 resources have 8 policy violations, 10 resources unevaluated\n"
        )

        status, exit_code, stats = analyze_scan_results(temp_file, 1)
        assert status == "❌ Failed with errors; incomplete scan"
        assert exit_code == 1
        assert stats["compliant"] == 30
        assert stats["total"] == 100
        assert stats["violating_resources"] == 60
        assert stats["violating_policies"] == 8
        assert stats["unevaluated"] == 10

    def test_no_stats_line(self, tmp_path):
        """Test analysis when stats line is missing."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text("Some output without stats\n")

        status, exit_code, stats = analyze_scan_results(temp_file, 0)
        assert status == "✅ Passed"
        assert exit_code == 0
        assert stats["compliant"] == 0
        assert stats["total"] == 0
        assert stats["violating_policies"] == 0

    def test_subprocess_error(self, tmp_path):
        """Test analysis when subprocess fails without completing scan."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text("Error: Network timeout\nConnection failed\n")

        status, exit_code, stats = analyze_scan_results(temp_file, 1)
        assert status == "❌ Error running scan"
        assert exit_code == 1
        assert stats["compliant"] == 0
        assert stats["total"] == 0

    def test_subprocess_exit_nonzero_but_scan_completed(self, tmp_path):
        """Test that non-zero exit with completed scan is still treated as failure."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text(
            "Evaluation complete 0.02 seconds -> Success\n"
            "50 compliant of 100 total, 50 resources unevaluated\n"
        )

        # Subprocess exited non-zero but scan completed (edge case)
        status, exit_code, stats = analyze_scan_results(temp_file, 1)
        assert status == "❌ Failed"
        assert exit_code == 1
        assert stats["compliant"] == 50
        assert stats["total"] == 100


class TestExtractEvalResults:
    """Test evaluation results extraction logic."""

    def test_extract_from_eval_complete(self, tmp_path):
        """Test extracting results from 'Evaluation complete' onward."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text(
            "Earlier output\n"
            "More output\n"
            "Evaluation complete 0.01 seconds -> Success\n"
            "Stats line\n"
            "Results table\n"
        )

        result = extract_eval_results(temp_file)
        assert "Evaluation complete" in result
        assert "Stats line" in result
        assert "Results table" in result
        assert "Earlier output" not in result

    def test_no_eval_complete(self, tmp_path):
        """Test extraction when 'Evaluation complete' is not present."""
        temp_file = tmp_path / "output.txt"
        temp_file.write_text("All output\nShould be included\n")

        result = extract_eval_results(temp_file)
        assert "All output" in result
        assert "Should be included" in result


class TestBuildSummaryText:
    """Test summary text building logic."""

    def test_failed_with_violations(self):
        """Test summary for failed scan with violations."""
        stats = {
            "compliant": 40,
            "total": 100,
            "violating_resources": 45,
            "violating_policies": 12,
            "unevaluated": 15,
        }
        result = build_summary_text("❌ Failed", 1, stats)
        assert result == "❌ Failed - 12 policy violations"

    def test_passed_with_compliant(self):
        """Test summary for passed scan with compliant count."""
        stats = {
            "compliant": 56,
            "total": 423,
            "violating_resources": 0,
            "violating_policies": 0,
            "unevaluated": 367,
        }
        result = build_summary_text("✅ Passed", 0, stats)
        assert result == "✅ Passed - 56 compliant"

    def test_failed_no_violations_count(self):
        """Test summary for failed scan without violations shows just status."""
        stats = {
            "compliant": 40,
            "total": 100,
            "violating_resources": 0,
            "violating_policies": 0,
            "unevaluated": 0,
        }
        result = build_summary_text("❌ Failed", 1, stats)
        assert result == "❌ Failed"

    def test_failed_with_compliant_but_no_violations(self):
        """Test that failure without violations does not show misleading compliant count."""
        stats = {
            "compliant": 40,
            "total": 100,
            "violating_resources": 0,
            "violating_policies": 0,
            "unevaluated": 0,
        }
        result = build_summary_text("❌ Failed", 1, stats)
        assert result == "❌ Failed"
        assert "compliant" not in result

    def test_no_metrics(self):
        """Test summary with no metrics available."""
        stats = {
            "compliant": 0,
            "total": 0,
            "violating_resources": 0,
            "violating_policies": 0,
            "unevaluated": 0,
        }
        result = build_summary_text("✅ Passed", 0, stats)
        assert result == "✅ Passed"


class TestBuildDetailSection:
    """Test detail section building logic."""

    def test_build_collapsible_section(self):
        """Test building collapsible HTML section."""
        directory = "terraform/prod"
        summary = "✅ Passed - 56 compliant"
        eval_results = "Evaluation complete\nStats\nTable"

        result = build_detail_section(directory, summary, eval_results)

        assert "<details>" in result
        assert "<summary>" in result
        assert f"<code>{directory}</code>" in result
        assert f"({summary})" in result
        assert "<pre>" in result
        assert "</pre>" in result
        assert eval_results in result
        assert "</details>" in result

    def test_special_characters_in_directory(self):
        """Test building section with HTML-significant characters in directory path."""
        directory = "terraform/<prod>&main"
        summary = "✅ Passed - 100 compliant"
        eval_results = "Results here"

        result = build_detail_section(directory, summary, eval_results)

        assert "terraform/&lt;prod&gt;&amp;main" in result
        assert "<prod>" not in result


class TestUpdateOverallStatus:
    """Test overall status update logic."""

    def test_passed_then_passed(self):
        """Test: Passed + Passed = Passed."""
        status, exit_code = update_overall_status("✅ Passed", 0, "✅ Passed", 0)
        assert status == "✅ Passed"
        assert exit_code == 0

    def test_passed_then_warning(self):
        """Test: Passed + Warning = Warning."""
        status, exit_code = update_overall_status(
            "✅ Passed", 0, "⚠️ Passed with errors; incomplete scan", 0
        )
        assert status == "⚠️ Passed with warnings"
        assert exit_code == 0

    def test_passed_then_failed(self):
        """Test: Passed + Failed = Failed."""
        status, exit_code = update_overall_status("✅ Passed", 0, "❌ Failed", 1)
        assert status == "❌ Failed"
        assert exit_code == 1

    def test_passed_then_failed_with_errors(self):
        """Test: Passed + Failed with errors = Failed."""
        status, exit_code = update_overall_status(
            "✅ Passed", 0, "❌ Failed with errors; incomplete scan", 1
        )
        assert status == "❌ Failed"
        assert exit_code == 1

    def test_warning_then_passed(self):
        """Test: Warning + Passed = Warning (warnings persist)."""
        status, exit_code = update_overall_status("⚠️ Passed with warnings", 0, "✅ Passed", 0)
        assert status == "⚠️ Passed with warnings"
        assert exit_code == 0

    def test_warning_then_warning(self):
        """Test: Warning + Warning = Warning."""
        status, exit_code = update_overall_status(
            "⚠️ Passed with warnings", 0, "⚠️ Passed with errors; incomplete scan", 0
        )
        assert status == "⚠️ Passed with warnings"
        assert exit_code == 0

    def test_warning_then_failed(self):
        """Test: Warning + Failed = Failed (failure takes priority)."""
        status, exit_code = update_overall_status("⚠️ Passed with warnings", 0, "❌ Failed", 1)
        assert status == "❌ Failed"
        assert exit_code == 1

    def test_warning_then_failed_with_errors(self):
        """Test: Warning + Failed with errors = Failed."""
        status, exit_code = update_overall_status(
            "⚠️ Passed with warnings", 0, "❌ Failed with errors; incomplete scan", 1
        )
        assert status == "❌ Failed"
        assert exit_code == 1

    def test_failed_then_passed(self):
        """Test: Failed + Passed = Failed (failure persists)."""
        status, exit_code = update_overall_status("❌ Failed", 1, "✅ Passed", 0)
        assert status == "❌ Failed"
        assert exit_code == 1

    def test_failed_then_warning(self):
        """Test: Failed + Warning = Failed (failure persists)."""
        status, exit_code = update_overall_status(
            "❌ Failed", 1, "⚠️ Passed with errors; incomplete scan", 0
        )
        assert status == "❌ Failed"
        assert exit_code == 1

    def test_failed_then_failed(self):
        """Test: Failed + Failed = Failed."""
        status, exit_code = update_overall_status("❌ Failed", 1, "❌ Failed", 1)
        assert status == "❌ Failed"
        assert exit_code == 1

    def test_failed_then_failed_with_errors(self):
        """Test: Failed + Failed with errors = Failed."""
        status, exit_code = update_overall_status(
            "❌ Failed", 1, "❌ Failed with errors; incomplete scan", 1
        )
        assert status == "❌ Failed"
        assert exit_code == 1

    def test_multiple_scans_mixed_results(self):
        """Test: Multiple scans with mixed results properly prioritize failures."""
        # Start with passed
        status, exit_code = "✅ Passed", 0

        # Add passed scan
        status, exit_code = update_overall_status(status, exit_code, "✅ Passed", 0)
        assert status == "✅ Passed"
        assert exit_code == 0

        # Add warning scan
        status, exit_code = update_overall_status(
            status, exit_code, "⚠️ Passed with errors; incomplete scan", 0
        )
        assert status == "⚠️ Passed with warnings"
        assert exit_code == 0

        # Add another passed scan (should maintain warnings)
        status, exit_code = update_overall_status(status, exit_code, "✅ Passed", 0)
        assert status == "⚠️ Passed with warnings"
        assert exit_code == 0

        # Add failed scan (should upgrade to failed)
        status, exit_code = update_overall_status(status, exit_code, "❌ Failed", 1)
        assert status == "❌ Failed"
        assert exit_code == 1

        # Add another passed scan (should stay failed)
        status, exit_code = update_overall_status(status, exit_code, "✅ Passed", 0)
        assert status == "❌ Failed"
        assert exit_code == 1


class TestAggregateStats:
    """Test statistics aggregation logic."""

    def test_aggregate_single_scan(self):
        """Test aggregating stats from a single scan."""
        all_stats = [
            {
                "compliant": 56,
                "total": 423,
                "violating_resources": 0,
                "violating_policies": 0,
                "unevaluated": 367,
            }
        ]
        totals = aggregate_stats(all_stats)
        assert totals["compliant"] == 56
        assert totals["total"] == 423
        assert totals["violating_resources"] == 0
        assert totals["violating_policies"] == 0
        assert totals["unevaluated"] == 367

    def test_aggregate_multiple_scans(self):
        """Test aggregating stats from multiple scans."""
        all_stats = [
            {
                "compliant": 50,
                "total": 100,
                "violating_resources": 10,
                "violating_policies": 5,
                "unevaluated": 40,
            },
            {
                "compliant": 30,
                "total": 80,
                "violating_resources": 20,
                "violating_policies": 15,
                "unevaluated": 30,
            },
            {
                "compliant": 70,
                "total": 120,
                "violating_resources": 0,
                "violating_policies": 0,
                "unevaluated": 50,
            },
        ]
        totals = aggregate_stats(all_stats)
        assert totals["compliant"] == 150
        assert totals["total"] == 300
        assert totals["violating_resources"] == 30
        assert totals["violating_policies"] == 20
        assert totals["unevaluated"] == 120

    def test_aggregate_empty_stats(self):
        """Test aggregating empty stats list."""
        all_stats = []
        totals = aggregate_stats(all_stats)
        assert totals["compliant"] == 0
        assert totals["total"] == 0


class TestBuildAggregateSummary:
    """Test aggregate summary building logic."""

    def test_summary_with_all_stats(self):
        """Test building summary with all statistics present."""
        totals = {
            "compliant": 150,
            "total": 300,
            "violating_resources": 30,
            "violating_policies": 20,
            "unevaluated": 120,
        }
        result = build_aggregate_summary("❌ Failed", totals)
        assert (
            result
            == "❌ Failed - 150 compliant of 300 total - 30 resources have 20 policy violations - 120 resources unevaluated"
        )

    def test_summary_no_violations(self):
        """Test building summary with no violations."""
        totals = {
            "compliant": 200,
            "total": 300,
            "violating_resources": 0,
            "violating_policies": 0,
            "unevaluated": 100,
        }
        result = build_aggregate_summary("✅ Passed", totals)
        assert result == "✅ Passed - 200 compliant of 300 total - 100 resources unevaluated"

    def test_summary_no_unevaluated(self):
        """Test building summary with no unevaluated resources."""
        totals = {
            "compliant": 150,
            "total": 180,
            "violating_resources": 30,
            "violating_policies": 20,
            "unevaluated": 0,
        }
        result = build_aggregate_summary("❌ Failed", totals)
        assert (
            result
            == "❌ Failed - 150 compliant of 180 total - 30 resources have 20 policy violations"
        )


class TestFormatResults:
    """Test result formatting based on scenario."""

    def test_single_directory_format(self):
        """Test formatting for single directory - direct output with pre block."""
        wrapped_results = safe_code_block("Evaluation complete\nStats\nTable")
        result = format_results(
            is_recursive=False,
            overall_status="✅ Passed",
            outputs=[wrapped_results],
            totals={},
        )
        assert result == wrapped_results
        assert "<details>" not in result
        assert "<pre>" in result

    def test_multiple_dirs_not_recursive(self):
        """Test formatting for multiple directories without recursion."""
        outputs = ["<details>dir1</details>", "<details>dir2</details>"]
        result = format_results(
            is_recursive=False,
            overall_status="✅ Passed",
            outputs=outputs,
            totals={},
        )
        assert result == "<details>dir1</details>\n\n<details>dir2</details>"
        # Should not have outer wrapper
        assert result.count("<details>") == 2

    def test_multiple_dirs_recursive(self):
        """Test formatting for multiple directories with recursion - outer wrapper."""
        outputs = ["<details>dir1</details>", "<details>dir2</details>"]
        totals = {
            "compliant": 100,
            "total": 200,
            "violating_resources": 10,
            "violating_policies": 5,
            "unevaluated": 90,
        }
        result = format_results(
            is_recursive=True,
            overall_status="❌ Failed",
            outputs=outputs,
            totals=totals,
        )
        # Should have outer wrapper plus inner details
        assert result.count("<details>") == 3
        assert "❌ Failed - 100 compliant of 200 total" in result
        assert "<details>dir1</details>" in result
        assert "<details>dir2</details>" in result


class TestFindTerraformDirectories:
    """Test recursive Terraform directory discovery."""

    def test_finds_tf_files(self, tmp_path):
        """Test finding directories containing .tf files."""
        (tmp_path / "module_a").mkdir()
        (tmp_path / "module_a" / "main.tf").touch()
        (tmp_path / "module_b").mkdir()
        (tmp_path / "module_b" / "main.tf").touch()
        (tmp_path / "no_tf").mkdir()
        (tmp_path / "no_tf" / "readme.md").touch()

        result = find_terraform_directories([str(tmp_path)])
        assert len(result) == 2
        assert str(tmp_path / "module_a") in result
        assert str(tmp_path / "module_b") in result

    def test_nonexistent_directory(self, tmp_path):
        """Test that nonexistent directories are skipped with a warning."""
        result = find_terraform_directories([str(tmp_path / "does_not_exist")])
        assert result == []

    def test_no_tf_files(self, tmp_path):
        """Test that directories without .tf files return empty."""
        (tmp_path / "empty").mkdir()
        result = find_terraform_directories([str(tmp_path)])
        assert result == []

    def test_nested_tf_files(self, tmp_path):
        """Test finding nested .tf files."""
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        (nested / "main.tf").touch()

        result = find_terraform_directories([str(tmp_path)])
        assert result == [str(nested)]

    def test_skips_hidden_directories(self, tmp_path):
        """Test that hidden directories like .terraform are skipped."""
        # Real module
        (tmp_path / "module").mkdir()
        (tmp_path / "module" / "main.tf").touch()
        # Vendored provider source inside .terraform
        dot_tf = tmp_path / "module" / ".terraform" / "providers"
        dot_tf.mkdir(parents=True)
        (dot_tf / "provider.tf").touch()

        result = find_terraform_directories([str(tmp_path)])
        assert len(result) == 1
        assert str(tmp_path / "module") in result


class TestWriteGithubOutput:
    """Test GitHub Actions output writing."""

    def test_write_single_line(self, tmp_path):
        """Test writing a simple key=value output."""
        output_file = tmp_path / "github_output"
        output_file.touch()

        write_github_output("MY_KEY", "my_value", str(output_file))

        content = output_file.read_text()
        assert content == "MY_KEY=my_value\n"

    def test_write_with_emoji(self, tmp_path):
        """Test writing output containing emoji characters."""
        output_file = tmp_path / "github_output"
        output_file.touch()

        write_github_output("STATUS", "✅ Passed", str(output_file))

        content = output_file.read_text()
        assert content == "STATUS=✅ Passed\n"

    def test_rejects_newline_in_value(self, tmp_path):
        """Test that newlines in value raise ValueError."""
        output_file = tmp_path / "github_output"
        output_file.touch()

        with pytest.raises(ValueError, match="contains newlines"):
            write_github_output("BAD", "line1\nline2", str(output_file))

    def test_appends_to_existing(self, tmp_path):
        """Test that outputs are appended, not overwritten."""
        output_file = tmp_path / "github_output"
        output_file.touch()

        write_github_output("KEY1", "val1", str(output_file))
        write_github_output("KEY2", "val2", str(output_file))

        content = output_file.read_text()
        assert content == "KEY1=val1\nKEY2=val2\n"


class TestWriteGithubMultilineOutput:
    """Test GitHub Actions multiline output writing."""

    def test_write_multiline(self, tmp_path):
        """Test writing multiline output with delimiter."""
        output_file = tmp_path / "github_output"
        output_file.touch()

        write_github_multiline_output("RESULTS", "line1\nline2\nline3", str(output_file))

        content = output_file.read_text()
        # Format: NAME<<DELIMITER\nvalue\nDELIMITER\n
        assert content.startswith("RESULTS<<")
        assert "line1\nline2\nline3" in content
        # Delimiter should appear twice (opening and closing)
        lines = content.strip().split("\n")
        delimiter = lines[0].split("<<")[1]
        assert lines[-1] == delimiter


class TestBuildDetailSectionEscaping:
    """Test HTML escaping in detail sections."""

    def test_html_in_directory_is_escaped(self):
        """Test that HTML characters in directory names are escaped."""
        directory = '<img src=x onerror="alert(1)">'
        summary = "✅ Passed"
        eval_results = "Results here"

        result = build_detail_section(directory, summary, eval_results)

        assert "<img" not in result
        assert "&lt;img" in result
        assert "onerror" not in result or "&quot;" in result

    def test_ampersand_in_directory_is_escaped(self):
        """Test that ampersands in directory names are escaped."""
        directory = "terraform/a&b"
        result = build_detail_section(directory, "✅ Passed", "results")
        assert "a&amp;b" in result

    def test_html_in_eval_results_is_escaped(self):
        """Test that HTML in scan output is escaped inside the code block."""
        result = safe_code_block('<script>alert("xss")</script>')
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_html_in_summary_text_is_escaped(self):
        """Test that HTML in summary text is escaped."""
        result = build_detail_section("dir", '<img onerror="alert(1)">', "results")
        assert "<img" not in result
        assert "&lt;img" in result


class TestRunAllScans:
    """Test run_all_scans orchestration across multiple directories."""

    @staticmethod
    def _make_fake_popen(outputs):
        """Create a fake Popen that yields different output per invocation.

        Args:
            outputs: list of (output_text, returncode) tuples, one per call

        """
        call_idx = [0]

        def fake_popen(cmd, **kwargs):
            text, rc = outputs[call_idx[0]]
            call_idx[0] += 1
            mock = MagicMock()
            mock.stdout = iter(text.splitlines(keepends=True))
            mock.returncode = rc
            return mock

        return fake_popen

    def test_single_directory_no_details_wrapper(self):
        """Single directory should produce a <pre> block, not <details>."""
        fake = self._make_fake_popen([
            ("Evaluation complete 0.01s -> Success\n10 compliant of 10 total\n", 0),
        ])
        with patch("run_sinistral_scans.subprocess.Popen", side_effect=fake):
            status, exit_code, outputs, all_stats = run_all_scans(
                ["terraform"], project="P", cli_version="v1"
            )

        assert status == "✅ Passed"
        assert exit_code == 0
        assert len(outputs) == 1
        assert "<pre>" in outputs[0]
        assert "<details>" not in outputs[0]
        assert all_stats[0]["compliant"] == 10

    def test_multiple_directories_produce_detail_sections(self):
        """Multiple directories should produce <details> blocks."""
        fake = self._make_fake_popen([
            ("Evaluation complete 0.01s -> Success\n5 compliant of 5 total\n", 0),
            (
                "Evaluation complete 0.02s -> Failure\n2 compliant of 10 total, 3 resources have 4 policy violations\n",
                1,
            ),
        ])
        with patch("run_sinistral_scans.subprocess.Popen", side_effect=fake):
            status, exit_code, outputs, all_stats = run_all_scans(
                ["dir_a", "dir_b"], project="P", cli_version="v1"
            )

        assert status == "❌ Failed"
        assert exit_code == 1
        assert len(outputs) == 2
        assert all("<details>" in o for o in outputs)
        assert all_stats[0]["compliant"] == 5
        assert all_stats[1]["violating_policies"] == 4

    def test_mixed_pass_and_warning(self):
        """A warning scan should escalate overall status to warning."""
        fake = self._make_fake_popen([
            ("Evaluation complete 0.01s -> Success\n5 compliant of 5 total\n", 0),
            (
                "Traceback (most recent call last):\n  err\nEvaluation complete 0.01s -> Success\n3 compliant of 3 total\n",
                0,
            ),
        ])
        with patch("run_sinistral_scans.subprocess.Popen", side_effect=fake):
            status, exit_code, _outputs, _ = run_all_scans(
                ["dir_a", "dir_b"], project="P", cli_version="v1"
            )

        assert status == "⚠️ Passed with warnings"
        assert exit_code == 0

    def test_subprocess_error_without_scan_completion(self):
        """A subprocess error with no scan output should report error status."""
        fake = self._make_fake_popen([
            ("Error: connection refused\n", 1),
        ])
        with patch("run_sinistral_scans.subprocess.Popen", side_effect=fake):
            status, exit_code, _outputs, _ = run_all_scans(
                ["terraform"], project="P", cli_version="v1"
            )

        assert "❌" in status
        assert exit_code == 1


class TestMain:
    """Integration tests for main() orchestration."""

    def test_single_directory_produces_correct_outputs(self, tmp_path, monkeypatch):
        """Test main() with a single directory writes correct GitHub outputs."""
        github_output = tmp_path / "github_output"
        github_output.touch()

        scan_output = (
            "Evaluation complete 0.01 seconds -> Success\n"
            "56 compliant of 100 total, 44 resources unevaluated\n"
        )

        def fake_popen(cmd, **kwargs):
            mock = MagicMock()
            mock.stdout = iter(scan_output.splitlines(keepends=True))
            mock.returncode = 0
            return mock

        monkeypatch.setattr("run_sinistral_scans.subprocess.Popen", fake_popen)
        monkeypatch.setattr(
            "sys.argv",
            [
                "run_sinistral_scans.py",
                "--iac-directories",
                "terraform",
                "--project",
                "TestProject",
                "--cli-version",
                "v0.5.34",
                "--github-output",
                str(github_output),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

        content = github_output.read_text()
        assert "OVERALL_STATUS=✅ Passed" in content
        assert "EXIT_CODE=0" in content
        assert "SINISTRAL_RESULTS<<" in content
        assert "56 compliant of 100 total" in content

    def test_scan_failure_produces_failed_status(self, tmp_path, monkeypatch):
        """Test main() with a failing scan writes failure outputs."""
        github_output = tmp_path / "github_output"
        github_output.touch()

        scan_output = (
            "Evaluation complete 0.02 seconds -> Failure\n"
            "10 compliant of 50 total, 30 resources have 8 policy violations\n"
        )

        def fake_popen(cmd, **kwargs):
            mock = MagicMock()
            mock.stdout = iter(scan_output.splitlines(keepends=True))
            mock.returncode = 1
            return mock

        monkeypatch.setattr("run_sinistral_scans.subprocess.Popen", fake_popen)
        monkeypatch.setattr(
            "sys.argv",
            [
                "run_sinistral_scans.py",
                "--iac-directories",
                "terraform",
                "--project",
                "TestProject",
                "--cli-version",
                "v0.5.34",
                "--github-output",
                str(github_output),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

        content = github_output.read_text()
        assert "OVERALL_STATUS=❌ Failed" in content
        assert "EXIT_CODE=1" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
