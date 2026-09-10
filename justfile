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
    #!/usr/bin/env bash
    set -euo pipefail
    repo=stacklet/sinistral-cli
    ref={{quote(ref)}}

    # `sed -i` is not portable: BSD sed reads the next argument as a backup
    # suffix. Write through a temp file, then copy back so the target keeps its
    # own inode and permissions.
    edit() {
        local expr="$1" file="$2" tmp
        tmp="$(mktemp "${file}.XXXXXX")"
        sed -E "$expr" "$file" > "$tmp" && cat "$tmp" > "$file"
        rm -f "$tmp"
    }

    if [ "$ref" = "latest" ]; then
        ref="$(gh api "repos/${repo}/releases/latest" --jq .tag_name)"
    fi

    # One call resolves any ref (tag, branch, full or short SHA) to its commit.
    read -r sha date < <(gh api "repos/${repo}/commits/${ref}" \
        --jq '[.sha, (.commit.committer.date | split("T")[0])] | @tsv')

    # Prefer a tag pointing at that exact commit for the human-readable comment;
    # otherwise fall back to what was asked for, dated so it stays meaningful.
    tags="$(gh api --paginate "repos/${repo}/tags?per_page=100" \
        --jq ".[] | select(.commit.sha == \"${sha}\") | .name")"
    name="${tags%%$'\n'*}"
    if [ -z "$name" ]; then
        case "$sha" in
            "$ref"*) name="${sha:0:7} (${date})" ;;
            *) name="${ref} (${date})" ;;
        esac
    fi

    # Ref names allow characters that are special to sed's replacement side.
    esc="${name//\\/\\\\}"; esc="${esc//&/\\&}"; esc="${esc//@/\\@}"

    # action.yml and README.md are checked independently: either can be stale on
    # its own, so neither is skipped just because the other is already correct.
    changed=""

    cur_sha=""; cur_name=""
    read -r cur_sha cur_name < <(sed -n -E \
        "/^  sinistral_cli_version:/,/^  [a-z_]+:/ s@^ +default: '([^']*)'( *# *(.*))?\$@\1 \3@p" \
        action.yml) || true
    if [ "$cur_sha" != "$sha" ] || [ "$cur_name" != "$name" ]; then
        edit "/^  sinistral_cli_version:/,/^  [a-z_]+:/ s@^( +default: ).*\$@\1'${sha}' # ${esc}@" action.yml
        changed="${changed}action.yml "
    fi

    cur_doc="$(sed -n -E 's@^\| `sinistral_cli_version` \| No \| `([^`]*)`.*@\1@p' README.md)"
    if [ "$cur_doc" != "$name" ]; then
        edit "s@(\| \`sinistral_cli_version\` \| No \| \`)[^\`]*(\`)@\1${esc}\2@" README.md
        changed="${changed}README.md "
    fi

    if [ -z "$changed" ]; then
        echo "Already pinned to ${sha} # ${name}; action.yml and README.md both current"
    else
        echo "Pinned to ${sha} # ${name}"
        echo "updated: ${changed% }"
    fi
