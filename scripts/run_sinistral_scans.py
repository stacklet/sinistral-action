"""Run Sinistral IaC scans across multiple directories and aggregate results."""
# Copyright (c) 2026 - Stacklet, Inc.

import argparse
import base64
import html
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def parse_directories(iac_dirs_input: str) -> list[str]:
    """Parse newline-separated directory input, filtering empty lines."""
    return [line.strip() for line in iac_dirs_input.strip().split("\n") if line.strip()]


def find_terraform_directories(base_dirs: list[str]) -> list[str]:
    """Recursively find all directories containing .tf files."""
    tf_dirs = set()

    for base_dir in base_dirs:
        base_path = Path(base_dir.strip())
        if not base_path.exists():
            print(f"WARNING: Directory does not exist: {base_dir}")
            continue

        print(f"Searching for Terraform files in: {base_dir}")

        # Walk the tree without following symlinks to avoid cycles and escaping the checkout
        for root, dirs, files in os.walk(str(base_path), followlinks=False):
            # Skip hidden directories (e.g. .terraform) to avoid vendored provider source
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            if any(f.endswith(".tf") for f in files):
                tf_dirs.add(root)

    # Sort and return
    sorted_dirs = sorted(tf_dirs)
    if sorted_dirs:
        print(f"Found {len(sorted_dirs)} directories with Terraform files")
    else:
        print("WARNING: No directories with .tf files found")

    return sorted_dirs


def run_sinistral_scan(directory: str, output_file: Path, project: str, cli_version: str) -> int:
    """Run sinistral scan for a directory and save output to file.

    Returns:
        The subprocess exit code

    """
    print("=" * 40)
    print(f"Scanning directory: {directory}")
    print("=" * 40)

    cmd = [
        "uvx",
        "--from",
        f"git+https://github.com/stacklet/sinistral-cli@{cli_version}",
        "sinistral",
        "run",
        "--project",
        project,
        "-d",
        directory,
        "-o",
        "github",
    ]

    # Run command and tee output to both stdout and file
    with output_file.open("w", encoding="utf-8") as f:
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except FileNotFoundError:
            error_msg = f"ERROR: '{cmd[0]}' not found. Is it installed and on PATH?\n"
            print(error_msg, end="")
            f.write(error_msg)
            return 1

        if process.stdout is not None:
            for line in process.stdout:
                print(line, end="")
                f.write(line)

        try:
            process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            error_msg = "ERROR: sinistral scan timed out after 600 seconds\n"
            print(error_msg, end="")
            f.write(error_msg)
            return 1

    return process.returncode


def analyze_scan_results(output_file: Path, subprocess_exit_code: int) -> tuple[str, int, dict]:
    """Analyze scan output to determine status, exit code, and metrics.

    Args:
        output_file: Path to the scan output file
        subprocess_exit_code: The exit code from the subprocess that ran the scan

    Returns:
        Tuple of (status_emoji, exit_code, stats_dict)
        where stats_dict contains:
            - compliant: number of compliant resources
            - total: total number of resources
            - violating_resources: number of resources with violations
            - violating_policies: number of policy violations
            - unevaluated: number of unevaluated resources

    """
    output = output_file.read_text(encoding="utf-8")

    has_traceback = "Traceback" in output
    has_failure = bool(re.search(r"Evaluation complete.*Failure", output))
    scan_completed = "Evaluation complete" in output or bool(
        re.search(r"\d+ compliant of \d+ total", output)
    )

    # Determine status and exit code
    # If subprocess failed AND scan didn't complete, it's a subprocess error
    if subprocess_exit_code != 0 and not scan_completed:
        status = "❌ Error running scan"
        exit_code = 1
    elif has_traceback and (has_failure or subprocess_exit_code != 0):
        status = "❌ Failed with errors; incomplete scan"
        exit_code = 1
    elif has_failure or subprocess_exit_code != 0:
        status = "❌ Failed"
        exit_code = 1
    elif has_traceback:
        status = "⚠️ Passed with errors; incomplete scan"
        exit_code = 0
    else:
        status = "✅ Passed"
        exit_code = 0

    # Parse stats line (contains "compliant of")
    # Format: "X compliant of Y total[, Z resources have W policy violations][, M resources unevaluated]"
    stats = {
        "compliant": 0,
        "total": 0,
        "violating_resources": 0,
        "violating_policies": 0,
        "unevaluated": 0,
    }

    # Parse "X compliant of Y total"
    compliant_match = re.search(r"(\d+) compliant of (\d+) total", output)
    if compliant_match:
        stats["compliant"] = int(compliant_match.group(1))
        stats["total"] = int(compliant_match.group(2))

    # Parse "Z resources have W policy violations"
    violations_match = re.search(r"(\d+) resources have (\d+) policy violations", output)
    if violations_match:
        stats["violating_resources"] = int(violations_match.group(1))
        stats["violating_policies"] = int(violations_match.group(2))

    # Parse "M resources unevaluated"
    unevaluated_match = re.search(r"(\d+) resources unevaluated", output)
    if unevaluated_match:
        stats["unevaluated"] = int(unevaluated_match.group(1))

    return status, exit_code, stats


def extract_eval_results(output_file: Path) -> str:
    """Extract evaluation results (from 'Evaluation complete' onward)."""
    with output_file.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    # Find the line with "Evaluation complete"
    eval_start = None
    for i, line in enumerate(lines):
        if "Evaluation complete" in line:
            eval_start = i
            break

    if eval_start is not None:
        return "".join(lines[eval_start:])
    return "".join(lines)


def build_summary_text(status: str, exit_code: int, stats: dict) -> str:
    """Build summary text with metrics for collapsible section."""
    if exit_code == 1 and stats["violating_policies"] > 0:
        return f"{status} - {stats['violating_policies']} policy violations"
    if exit_code == 0 and stats["compliant"] > 0:
        return f"{status} - {stats['compliant']} compliant"
    return status


def safe_code_block(text: str) -> str:
    """Wrap text in an HTML pre block, escaping entities to prevent markdown injection."""
    return f"<pre>\n{html.escape(text)}\n</pre>"


def build_detail_section(directory: str, summary_text: str, eval_results: str) -> str:
    """Build collapsible detail section for a directory."""
    safe_directory = html.escape(directory)
    safe_summary = html.escape(summary_text)
    code_block = safe_code_block(eval_results)
    return f"""<details>
<summary><code>{safe_directory}</code> ({safe_summary})</summary>

{code_block}
</details>"""


def aggregate_stats(all_stats: list[dict]) -> dict:
    """Aggregate statistics across all scan results."""
    totals = {
        "compliant": 0,
        "total": 0,
        "violating_resources": 0,
        "violating_policies": 0,
        "unevaluated": 0,
    }

    for stats in all_stats:
        totals["compliant"] += stats["compliant"]
        totals["total"] += stats["total"]
        totals["violating_resources"] += stats["violating_resources"]
        totals["violating_policies"] += stats["violating_policies"]
        totals["unevaluated"] += stats["unevaluated"]

    return totals


def build_aggregate_summary(overall_status: str, totals: dict) -> str:
    """Build summary text for aggregate stats across all scans."""
    parts = [overall_status]
    parts.append(f"{totals['compliant']} compliant of {totals['total']} total")

    if totals["violating_resources"] > 0:
        parts.append(
            f"{totals['violating_resources']} resources have {totals['violating_policies']} policy violations"
        )

    if totals["unevaluated"] > 0:
        parts.append(f"{totals['unevaluated']} resources unevaluated")

    return " - ".join(parts)


def format_results(
    *,
    is_recursive: bool,
    overall_status: str,
    outputs: list[str],
    totals: dict,
) -> str:
    """Format results based on scenario.

    - Single directory: Direct output with triple backticks, no collapsed blocks
    - Multiple directories (not recursive): Individual collapsed blocks
    - Multiple directories (recursive): Outer collapsed block with aggregate stats
    """
    if len(outputs) == 1:
        # Single directory: just the evaluation results (already wrapped in backticks)
        return outputs[0]

    if not is_recursive:
        # Multiple directories, not recursive: individual collapsed blocks
        return "\n\n".join(outputs)

    # Multiple directories, recursive: wrap in outer collapsed block with aggregate stats
    aggregate_summary = html.escape(build_aggregate_summary(overall_status, totals))
    inner_details = "\n\n".join(outputs)

    return f"""<details>
<summary>{aggregate_summary}</summary>

{inner_details}
</details>"""


def write_github_output(output_name: str, output_value: str, github_output_file: str) -> None:
    """Write a single-line output to GitHub Actions output file."""
    if "\n" in output_value:
        msg = f"output_value for {output_name} contains newlines; use write_github_multiline_output"
        raise ValueError(msg)
    with Path(github_output_file).open("a", encoding="utf-8") as f:
        f.write(f"{output_name}={output_value}\n")


def write_github_multiline_output(
    output_name: str, output_value: str, github_output_file: str
) -> None:
    """Write multiline output to GitHub Actions output file with random EOF delimiter."""
    # Generate random EOF delimiter for security
    eof = base64.b64encode(os.urandom(15)).decode()
    while eof in output_value:
        eof = base64.b64encode(os.urandom(15)).decode()

    with Path(github_output_file).open("a", encoding="utf-8") as f:
        f.write(f"{output_name}<<{eof}\n")
        f.write(output_value)
        f.write(f"\n{eof}\n")


def update_overall_status(
    current_overall_status: str,
    current_overall_exit_code: int,
    scan_status: str,
    scan_exit_code: int,
) -> tuple[str, int]:
    """Update overall status and exit code based on a new scan result.

    Priority order: Failed > Passed with warnings > Passed

    Args:
        current_overall_status: Current aggregated status
        current_overall_exit_code: Current aggregated exit code
        scan_status: Status from the latest scan
        scan_exit_code: Exit code from the latest scan

    Returns:
        Tuple of (new_overall_status, new_overall_exit_code)

    """
    new_exit_code = current_overall_exit_code
    new_status = current_overall_status

    # If this scan failed, update to failed
    if scan_exit_code == 1:
        new_exit_code = 1
        new_status = "❌ Failed"
    # If this scan has warnings and we haven't failed yet
    elif "⚠️" in scan_status and "❌" not in current_overall_status:
        new_status = "⚠️ Passed with warnings"

    return new_status, new_exit_code


def run_all_scans(
    iac_dirs: list[str], project: str, cli_version: str
) -> tuple[str, int, list[str], list[dict]]:
    """Run scans across all directories and collect results.

    Returns:
        Tuple of (overall_status, overall_exit_code, outputs, all_stats)

    """
    overall_exit_code = 0
    overall_status = "✅ Passed"
    outputs: list[str] = []
    all_stats: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="sinistral_") as tmp:
        temp_dir = Path(tmp)

        for idx, iac_dir in enumerate(iac_dirs):
            output_file = temp_dir / f"sinistral_{idx}.txt"

            subprocess_exit_code = run_sinistral_scan(iac_dir, output_file, project, cli_version)

            status, exit_code, stats = analyze_scan_results(output_file, subprocess_exit_code)
            all_stats.append(stats)

            overall_status, overall_exit_code = update_overall_status(
                overall_status, overall_exit_code, status, exit_code
            )

            eval_results = extract_eval_results(output_file)

            if len(iac_dirs) == 1:
                outputs.append(safe_code_block(eval_results))
            else:
                summary_text = build_summary_text(status, exit_code, stats)
                detail = build_detail_section(iac_dir, summary_text, eval_results)
                outputs.append(detail)

    return overall_status, overall_exit_code, outputs, all_stats


def main() -> None:
    """Parse arguments and run Sinistral scans across one or more directories."""
    parser = argparse.ArgumentParser(description="Run Sinistral scans across multiple directories")
    parser.add_argument(
        "--iac-directories", required=True, help="Newline-separated list of directories to scan"
    )
    parser.add_argument("--project", required=True, help="Sinistral project name")
    parser.add_argument(
        "--recurse", action="store_true", help="Recursively find directories with .tf files"
    )
    parser.add_argument(
        "--cli-version", required=True, help="sinistral-cli version (git ref) to use"
    )
    parser.add_argument("--github-output", required=True, help="Path to GitHub Actions output file")

    args = parser.parse_args()

    # Parse directories
    iac_dirs = parse_directories(args.iac_directories)

    if not iac_dirs:
        print("ERROR: No directories provided in iac_directories input")
        sys.exit(1)

    if args.recurse:
        print("Recurse enabled - discovering subdirectories with Terraform files")
        iac_dirs = find_terraform_directories(iac_dirs)

        if not iac_dirs:
            print("ERROR: No directories with .tf files found")
            sys.exit(1)

    overall_status, overall_exit_code, outputs, all_stats = run_all_scans(
        iac_dirs, args.project, args.cli_version
    )

    totals = aggregate_stats(all_stats)

    combined_results = format_results(
        is_recursive=args.recurse,
        overall_status=overall_status,
        outputs=outputs,
        totals=totals,
    )

    write_github_output("OVERALL_STATUS", overall_status, args.github_output)
    write_github_output("EXIT_CODE", str(overall_exit_code), args.github_output)
    write_github_multiline_output("SINISTRAL_RESULTS", combined_results, args.github_output)

    sys.exit(overall_exit_code)


if __name__ == "__main__":
    main()
