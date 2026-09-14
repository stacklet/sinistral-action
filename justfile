# Install dev dependencies
install:
    uv sync

# Run all linters via prek
lint:
    uvx prek run --all-files

# Run ruff formatter
format:
    uv run ruff format scripts/ tests/

# Run script unit tests
test:
    uv run pytest -v

# Bump the default sinistral_cli_version (ref: tag, branch, or SHA; default latest release)
bump-cli-version ref="latest":
    uv run scripts/bump_cli_version.py {{quote(ref)}}
