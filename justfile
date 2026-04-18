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
