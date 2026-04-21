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
