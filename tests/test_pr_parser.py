import pytest
from helpers.pr_parser import parse_pr


@pytest.mark.parametrize(
    "title,pkg,old,new,ecosystem",
    [
        (
            "Bump requests from 2.31.0 to 2.32.0",
            "requests",
            "2.31.0",
            "2.32.0",
            "pip",
        ),
        (
            "Bump requests from 2.31.0 to 2.32.0 in /foundations/hello_world",
            "requests",
            "2.31.0",
            "2.32.0",
            "pip",
        ),
        (
            "build(deps): bump litellm from 1.30.1 to 1.30.2",
            "litellm",
            "1.30.1",
            "1.30.2",
            "pip",
        ),
        (
            "Bump actions/checkout from 3 to 4",
            "actions/checkout",
            "3",
            "4",
            "pip",  # no branch → defaults to pip
        ),
    ],
)
def test_dependabot_titles(title, pkg, old, new, ecosystem):
    result = parse_pr(title)
    assert result is not None
    assert result.package == pkg
    assert result.old_version == old
    assert result.new_version == new
    assert result.ecosystem == ecosystem


@pytest.mark.parametrize(
    "title,pkg,new",
    [
        ("Update dependency requests to v2.32.0", "requests", "2.32.0"),
        ("chore(deps): update dependency litellm to 1.30.2", "litellm", "1.30.2"),
        ("Update dependency numpy to v2.0.0", "numpy", "2.0.0"),
        # "dependency" keyword is optional in some Renovate presets
        ("Update requests to v2.32.0", "requests", "2.32.0"),
        ("fix(deps): Update lodash to 4.17.21", "lodash", "4.17.21"),
        ("chore(deps): Update boto3 to 1.34.0", "boto3", "1.34.0"),
    ],
)
def test_renovate_titles(title, pkg, new):
    result = parse_pr(title)
    assert result is not None
    assert result.package == pkg
    assert result.new_version == new
    assert result.old_version == "unknown"  # no body → can't extract old version


def test_unknown_title_returns_none():
    assert parse_pr("Fix typo in README") is None
    assert parse_pr("chore: update CI config") is None
    # "Update X to Y" must not match when Y doesn't look like a version
    assert parse_pr("Update README to fix typo") is None
    assert parse_pr("Update tests to use new API") is None


# ---------------------------------------------------------------------------
# Renovate old-version extraction from PR body
# ---------------------------------------------------------------------------


def test_renovate_extracts_old_version_from_from_to_body():
    title = "Update dependency requests to v2.32.0"
    body = "| requests | from `2.31.0` to `2.32.0` |"
    result = parse_pr(title, body)
    assert result is not None
    assert result.old_version == "2.31.0"


def test_renovate_extracts_old_version_from_arrow_pattern():
    title = "Update dependency requests to v2.32.0"
    body = "| [requests](https://pypi.org/project/requests) | `2.31.0` -> `2.32.0` |"
    result = parse_pr(title, body)
    assert result is not None
    assert result.old_version == "2.31.0"


def test_renovate_arrow_without_backticks():
    title = "Update dependency requests to v2.32.0"
    body = "requests: 2.31.0 -> 2.32.0"
    result = parse_pr(title, body)
    assert result is not None
    assert result.old_version == "2.31.0"


def test_renovate_arrow_unicode():
    title = "Update dependency requests to v2.32.0"
    body = "| requests | 2.31.0 → 2.32.0 |"
    result = parse_pr(title, body)
    assert result is not None
    assert result.old_version == "2.31.0"


def test_renovate_v_prefix_in_body_stripped_for_comparison():
    # Body may say "v2.31.0 -> v2.32.0" while title says "to v2.32.0"
    title = "Update dependency requests to v2.32.0"
    body = "| requests | `v2.31.0` -> `v2.32.0` |"
    result = parse_pr(title, body)
    assert result is not None
    assert result.old_version == "v2.31.0"


def test_renovate_prerelease_version_extracted():
    title = "Update dependency mylib to 2.0.0"
    body = "| mylib | `1.0.0-rc.1` -> `2.0.0` |"
    result = parse_pr(title, body)
    assert result is not None
    assert result.old_version == "1.0.0-rc.1"


def test_renovate_no_false_positive_substring_match():
    # "xml" must not accidentally pull old version from the "xml-js" line
    title = "Update dependency xml to v1.0.1"
    body = (
        "| xml-js | `2.0.0` -> `2.0.1` |\n"
        "| xml | `1.0.0` -> `1.0.1` |\n"
    )
    result = parse_pr(title, body)
    assert result is not None
    assert result.old_version == "1.0.0"


def test_renovate_fallback_strategy_no_package_line():
    # Package name doesn't appear on the same line as the version transition;
    # strategy 3 (any matching arrow) should still find the old version.
    title = "Update dependency requests to 2.32.0"
    body = "This bump updates the HTTP library.\n\n`2.31.0` -> `2.32.0`\n"
    result = parse_pr(title, body)
    assert result is not None
    assert result.old_version == "2.31.0"


def test_renovate_uses_unknown_when_body_has_no_match():
    title = "Update dependency requests to v2.32.0"
    result = parse_pr(title, "No version info here.")
    assert result is not None
    assert result.old_version == "unknown"


# ---------------------------------------------------------------------------
# npm ecosystem detection
# ---------------------------------------------------------------------------


def test_dependabot_npm_branch_detected():
    result = parse_pr(
        "Bump lodash from 4.17.20 to 4.17.21",
        branch="dependabot/npm_and_yarn/lodash-4.17.21",
    )
    assert result is not None
    assert result.ecosystem == "npm"
    assert result.package == "lodash"


def test_dependabot_pip_branch_detected():
    result = parse_pr(
        "Bump requests from 2.31.0 to 2.32.0",
        branch="dependabot/pip/requests-2.32.0",
    )
    assert result is not None
    assert result.ecosystem == "pip"


def test_scoped_npm_package_detected():
    result = parse_pr("Bump @typescript-eslint/parser from 6.0.0 to 6.1.0")
    assert result is not None
    assert result.ecosystem == "npm"
    assert result.package == "@typescript-eslint/parser"


def test_scoped_npm_package_renovate():
    result = parse_pr("Update dependency @typescript-eslint/eslint-plugin to v6.1.0")
    assert result is not None
    assert result.ecosystem == "npm"
    assert result.package == "@typescript-eslint/eslint-plugin"


def test_unknown_branch_defaults_to_pip():
    result = parse_pr("Bump requests from 2.31.0 to 2.32.0", branch="feature/my-branch")
    assert result is not None
    assert result.ecosystem == "pip"


def test_dependabot_bundler_maps_to_rubygems():
    result = parse_pr(
        "Bump gem from 1.0.0 to 1.1.0",
        branch="dependabot/bundler/gem-1.1.0",
    )
    assert result is not None
    assert result.ecosystem == "rubygems"


def test_dependabot_unknown_ecosystem_slug_falls_back():
    result = parse_pr(
        "Bump some-pkg from 1.0.0 to 1.1.0",
        branch="dependabot/gradle/some-pkg-1.1.0",  # gradle not in the map
    )
    assert result is not None
    assert result.ecosystem == "pip"  # unknown slug → default


def test_dependabot_cargo_detected():
    result = parse_pr(
        "Bump serde from 1.0.100 to 1.0.200",
        branch="dependabot/cargo/serde-1.0.200",
    )
    assert result is not None
    assert result.ecosystem == "cargo"


# ---------------------------------------------------------------------------
# Renovate branch-based ecosystem detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "branch,expected_ecosystem",
    [
        ("renovate/npm-lodash-4.x", "npm"),
        ("renovate/node-express-5.x", "npm"),
        ("renovate/python-requests-2.x", "pip"),
        ("renovate/pypi-boto3-1.x", "pip"),
        ("renovate/ruby-rails-8.x", "rubygems"),
        ("renovate/bundler-devise-4.x", "rubygems"),
        ("renovate/gem-nokogiri-1.x", "rubygems"),
        ("renovate/cargo-serde-1.x", "cargo"),
        ("renovate/golang-github.com-gorilla-mux-1.x", "go"),
        ("renovate/gomod-rsc-quote-1.x", "go"),
        ("renovate/maven-com.example-1.x", "maven"),
        ("renovate/gradle-junit-4.x", "maven"),
        ("renovate/nuget-Newtonsoft.Json-13.x", "nuget"),
        ("renovate/composer-symfony-7.x", "composer"),
    ],
)
def test_renovate_branch_ecosystem_detected(branch, expected_ecosystem):
    title = "Update dependency requests to v2.32.0"
    result = parse_pr(title, branch=branch)
    assert result is not None
    assert result.ecosystem == expected_ecosystem


def test_renovate_unknown_branch_prefix_falls_back_to_pip():
    result = parse_pr(
        "Update dependency some-pkg to v1.2.0",
        branch="renovate/some-unknown-1.x",
    )
    assert result is not None
    assert result.ecosystem == "pip"


def test_renovate_branch_npm_with_scoped_package():
    result = parse_pr(
        "Update dependency @typescript-eslint/parser to v6.1.0",
        branch="renovate/npm-typescript-eslint-parser-6.x",
    )
    assert result is not None
    assert result.ecosystem == "npm"
    assert result.package == "@typescript-eslint/parser"
