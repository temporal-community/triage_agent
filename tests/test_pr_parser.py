import pytest
from helpers.pr_parser import parse_pr


@pytest.mark.parametrize("title,pkg,old,new", [
    (
        "Bump requests from 2.31.0 to 2.32.0",
        "requests", "2.31.0", "2.32.0",
    ),
    (
        "Bump requests from 2.31.0 to 2.32.0 in /foundations/hello_world",
        "requests", "2.31.0", "2.32.0",
    ),
    (
        "build(deps): bump litellm from 1.30.1 to 1.30.2",
        "litellm", "1.30.1", "1.30.2",
    ),
    (
        "Bump actions/checkout from 3 to 4",
        "actions/checkout", "3", "4",
    ),
])
def test_dependabot_titles(title, pkg, old, new):
    result = parse_pr(title)
    assert result is not None
    assert result.package == pkg
    assert result.old_version == old
    assert result.new_version == new


@pytest.mark.parametrize("title,pkg,new", [
    ("Update dependency requests to v2.32.0", "requests", "2.32.0"),
    ("chore(deps): update dependency litellm to 1.30.2", "litellm", "1.30.2"),
    ("Update dependency numpy to v2.0.0", "numpy", "2.0.0"),
])
def test_renovate_titles(title, pkg, new):
    result = parse_pr(title)
    assert result is not None
    assert result.package == pkg
    assert result.new_version == new


def test_unknown_title_returns_none():
    assert parse_pr("Fix typo in README") is None
    assert parse_pr("chore: update CI config") is None
