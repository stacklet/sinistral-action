# sinistral-action

GitHub Action for scanning Infrastructure as Code against
[Stacklet IaC Governance](https://stacklet.ai/iac-governance/) policies.

- **Pull requests** — results are posted (and updated) as a PR comment.
- **Push** — results appear in the Actions log.
- **Failure** — the action exits non-zero on policy violations, suitable for branch protection rules.

## Prerequisites

- A Stacklet account with a configured project.
- An OAuth2 client ID and secret for your project.

## Usage

```yaml
name: IaC

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sinistral:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write  # Required for posting PR comments
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: stacklet/sinistral-action@v1
        with:
          # Stacklet/Sinistral Instance Configuration (Required)
          sinistral_api_url: https://api.sinistral.example.com
          sinistral_auth_url: https://auth.console.example.com
          sinistral_project_client_id: ${{ secrets.SINISTRAL_CLIENT_ID }}
          sinistral_project_client_secret: ${{ secrets.SINISTRAL_CLIENT_SECRET }}
          sinistral_project: MyProject

          # Scanning Configuration (Required)
          iac_directories: terraform
```

### Multiple directories

```yaml
          iac_directories: |
            terraform/prod
            terraform/staging
```

### Recursive scanning

Discover all subdirectories containing `.tf` files automatically:

```yaml
          iac_directories: terraform
          recurse: true
```

### Skipping unchanged runs

By default the action skips the scan when the triggering push or pull request
changed no Terraform files (`.tf`, `.tf.json`, `.tfvars`, `.tfvars.json`) under
`iac_directories` — the only files a scan reads, so any other change can't
affect the result. The check runs before any toolchain setup, so a skipped run
costs only a few seconds — it pays for neither the scan nor the Python/uv
install.

The scanned directories come from `iac_directories` itself, and the check is
conservative: it matches the whole subtree, so under `recurse: false` it may
scan when only a subdirectory changed, but it never skips a file the scan would
read. The changed files are read from the GitHub
[compare API](https://docs.github.com/en/rest/commits/commits#compare-two-commits)
using the workflow's `github.token` (needs `contents: read`, which the action
already requires).

It **fails open** — if the changed files can't be determined (API error, a new
branch with no base, a diff larger than the API's 300-file cap, an unsupported
event), the scan runs. When a run is skipped the job still completes
**successfully** (with a `⏭️ Skipped` note in the log and job summary), so a
required `Sinistral / Scan IaC` status check stays green.

If an earlier revision posted a results comment and a later revision then skips
(e.g. the Terraform change was backed out), the skipped run replaces that
comment with a "Skipped" note (while `post_pr_comment` is enabled), so a stale —
possibly failing — comment can't contradict the green status. A skip never
creates a comment where none existed.

Set `skip_unchanged: 'false'` to always scan:

```yaml
          iac_directories: terraform
          skip_unchanged: 'false'
```

## Inputs

| Input | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `sinistral_api_url` | Yes | — | Base URL of your Sinistral API. |
| `sinistral_auth_url` | Yes | — | Auth URL for your Sinistral instance. |
| `sinistral_project_client_id` | Yes | — | OAuth2 client ID for your Sinistral project. |
| `sinistral_project_client_secret` | Yes | — | OAuth2 client secret for your Sinistral project. |
| `sinistral_project` | Yes | — | Sinistral project name to scan against. |
| `iac_directories` | Yes | — | Path(s) to IaC folders relative to the repo root. Newline-separated. |
| `recurse` | No | `false` | Recursively discover subdirectories containing `.tf` files. |
| `sinistral_cli_version` | No | `v0.5.34` | Git ref (tag, branch, SHA) of [sinistral-cli](https://github.com/stacklet/sinistral-cli). |
| `post_pr_comment` | No | `true` | Whether to post scan results as a PR comment. |
| `skip_unchanged` | No | `true` | Skip the scan when no Terraform files under `iac_directories` changed. Fails open. See [Skipping unchanged runs](#skipping-unchanged-runs). |

### Multiple Sinistral Projects

It can be useful to invoke this action more than once — for example, scanning against both a released set of policies and a "next" version. Use `post_pr_comment: false` on the secondary job so only the primary posts to the PR.
Set `continue-on-error: true` on the secondary job to prevent a failure there from blocking the PR.

```yaml
jobs:
  sinistral-primary:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v6
      - uses: stacklet/sinistral-action@v1
        with:
          sinistral_api_url: https://api.sinistral.example.com
          sinistral_auth_url: https://auth.console.example.com
          sinistral_project_client_id: ${{ secrets.SINISTRAL_PROJECT_CLIENT_ID }}
          sinistral_project_client_secret: ${{ secrets.SINISTRAL_PROJECT_CLIENT_SECRET }}
          sinistral_project: MyProject
          iac_directories: terraform

  sinistral-next:
    runs-on: ubuntu-latest
    continue-on-error: true  # Non-blocking
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v6
      - uses: stacklet/sinistral-action@v1
        with:
          sinistral_api_url: https://api.sinistral.example.com
          sinistral_auth_url: https://auth.console.example.com
          sinistral_project_client_id: ${{ secrets.SINISTRAL_NEXT_PROJECT_CLIENT_ID }}
          sinistral_project_client_secret: ${{ secrets.SINISTRAL_NEXT_PROJECT_CLIENT_SECRET }}
          sinistral_project: MyProject-next
          iac_directories: terraform
          post_pr_comment: 'false'
```

## Permissions

```yaml
permissions:
  contents: read
  pull-requests: write   # only needed for PR comment feature
```

## Versioning

Pin to a full-length commit SHA for supply-chain integrity
(tags are mutable). Tools like
[pinact](https://github.com/suzuki-shunsuke/pinact) can
automate this.

```yaml
uses: stacklet/sinistral-action@<FULL_COMMIT_SHA>
```

## License

MIT
