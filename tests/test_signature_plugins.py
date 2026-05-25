"""Tests for checks/signatures plugin loading.

Covers:
- _merge_yaml_dir: merges net_calls, obfuscation, persistence, file_types YAML
- _merge_contribution: merges SignatureContribution fields
- _load_plugins: discovers dependency_scout.signatures and
  dependency_scout.signature_providers entry points and merges them
- Graceful degradation: broken entry points are skipped with a warning
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

from checks.signatures import SignatureContribution, _load_plugins, _merge_contribution, _merge_yaml_dir


# ---------------------------------------------------------------------------
# _merge_yaml_dir
# ---------------------------------------------------------------------------


def _write(directory: Path, filename: str, content: str) -> None:
    (directory / filename).write_text(textwrap.dedent(content))


def test_merge_yaml_dir_net_calls(tmp_path):
    _write(tmp_path, "net_calls.yaml", """
        .py:
          - pattern: 'evil_sdk\\.call\\b'
            desc: test
    """)
    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_yaml_dir(tmp_path, acc)
    assert ".py" in acc["net_calls"]
    assert any(e["pattern"] == r"evil_sdk\.call\b" for e in acc["net_calls"][".py"])


def test_merge_yaml_dir_extends_existing_extension(tmp_path):
    _write(tmp_path, "net_calls.yaml", """
        .py:
          - pattern: 'new_pattern'
    """)
    acc = {"net_calls": {".py": [{"pattern": "existing"}]}, "obfuscation": {},
           "persistence": [], "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_yaml_dir(tmp_path, acc)
    assert len(acc["net_calls"][".py"]) == 2


def test_merge_yaml_dir_obfuscation(tmp_path):
    _write(tmp_path, "obfuscation.yaml", """
        patterns:
          .js:
            - pattern: '_0xdeadbeef'
    """)
    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_yaml_dir(tmp_path, acc)
    assert ".js" in acc["obfuscation"]


def test_merge_yaml_dir_persistence(tmp_path):
    _write(tmp_path, "persistence.yaml", """
        patterns:
          - pattern: 'evil\\.cron'
    """)
    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_yaml_dir(tmp_path, acc)
    assert any(e["pattern"] == r"evil\.cron" for e in acc["persistence"])


def test_merge_yaml_dir_file_types(tmp_path):
    _write(tmp_path, "file_types.yaml", """
        suspicious_filenames:
          - evil.cfg
        suspicious_path_prefixes:
          - .evil/
        dangerous_binary_suffixes:
          - .evil
        install_hook_names:
          - evil_install.sh
        npm_install_scripts:
          - evil_install
    """)
    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_yaml_dir(tmp_path, acc)
    assert "evil.cfg" in acc["suspicious_files"]
    assert ".evil/" in acc["suspicious_prefixes"]
    assert ".evil" in acc["dangerous_binary"]
    assert "evil_install.sh" in acc["install_hooks"]
    assert "evil_install" in acc["npm_install_scripts"]


def test_merge_yaml_dir_missing_files_are_skipped(tmp_path):
    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_yaml_dir(tmp_path, acc)  # no files present — should not raise
    assert acc["net_calls"] == {}
    assert acc["persistence"] == []


# ---------------------------------------------------------------------------
# _merge_contribution
# ---------------------------------------------------------------------------


def test_merge_contribution_net_calls():
    contrib = SignatureContribution(net_call_patterns={".py": [r"evil\.fetch\b"]})
    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_contribution(contrib, acc)
    assert r"evil\.fetch\b" in acc["net_calls"][".py"]


def test_merge_contribution_extends_existing():
    contrib = SignatureContribution(net_call_patterns={".py": ["new"]})
    acc = {"net_calls": {".py": ["existing"]}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_contribution(contrib, acc)
    assert "existing" in acc["net_calls"][".py"]
    assert "new" in acc["net_calls"][".py"]


def test_merge_contribution_persistence():
    contrib = SignatureContribution(persistence_patterns=[r"crontab.*evil"])
    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_contribution(contrib, acc)
    assert r"crontab.*evil" in acc["persistence"]


def test_merge_contribution_file_types():
    contrib = SignatureContribution(
        suspicious_package_files=["evil.cfg"],
        suspicious_package_prefixes=[".evil/"],
        dangerous_binary_suffixes=[".evil"],
        install_hook_names=["evil.sh"],
        npm_install_scripts=["evil_install"],
    )
    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    _merge_contribution(contrib, acc)
    assert "evil.cfg" in acc["suspicious_files"]
    assert ".evil/" in acc["suspicious_prefixes"]
    assert ".evil" in acc["dangerous_binary"]
    assert "evil.sh" in acc["install_hooks"]
    assert "evil_install" in acc["npm_install_scripts"]


def test_merge_contribution_empty_is_noop():
    contrib = SignatureContribution()
    acc = {"net_calls": {"existing": ["x"]}, "obfuscation": {}, "persistence": ["y"],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}
    before = {k: list(v) if isinstance(v, list) else dict(v) for k, v in acc.items()}
    _merge_contribution(contrib, acc)
    assert acc["net_calls"] == before["net_calls"]
    assert acc["persistence"] == before["persistence"]


# ---------------------------------------------------------------------------
# _load_plugins — entry point discovery
# ---------------------------------------------------------------------------


def test_load_plugins_signatures_entry_point(tmp_path):
    """dependency_scout.signatures entry point: callable returning a Path is merged."""
    (tmp_path / "net_calls.yaml").write_text(".go:\n  - pattern: 'plugin_pattern'\n")

    ep = MagicMock()
    ep.name = "test_plugin"
    ep.load.return_value = lambda: tmp_path

    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}

    def fake_entry_points(group):
        if group == "dependency_scout.signatures":
            return [ep]
        return []

    with patch("importlib.metadata.entry_points", side_effect=fake_entry_points):
        _load_plugins(acc)

    assert ".go" in acc["net_calls"]


def test_load_plugins_signature_providers_entry_point():
    """dependency_scout.signature_providers entry point: callable returning SignatureContribution."""
    contrib = SignatureContribution(persistence_patterns=[r"provider\.evil"])

    ep = MagicMock()
    ep.name = "test_provider"
    ep.load.return_value = lambda: contrib

    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}

    def fake_entry_points(group):
        if group == "dependency_scout.signature_providers":
            return [ep]
        return []

    with patch("importlib.metadata.entry_points", side_effect=fake_entry_points):
        _load_plugins(acc)

    assert r"provider\.evil" in acc["persistence"]


def test_load_plugins_broken_signatures_entry_point_skipped(caplog):
    """A broken dependency_scout.signatures entry point is skipped with a warning."""
    ep = MagicMock()
    ep.name = "broken_plugin"
    ep.load.side_effect = RuntimeError("boom")

    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}

    def fake_entry_points(group):
        if group == "dependency_scout.signatures":
            return [ep]
        return []

    with patch("importlib.metadata.entry_points", side_effect=fake_entry_points):
        with caplog.at_level("WARNING"):
            _load_plugins(acc)

    assert any("broken_plugin" in r.message for r in caplog.records)


def test_load_plugins_broken_provider_entry_point_skipped(caplog):
    """A broken dependency_scout.signature_providers entry point is skipped with a warning."""
    ep = MagicMock()
    ep.name = "broken_provider"
    ep.load.return_value = lambda: (_ for _ in ()).throw(ValueError("bad"))

    acc = {"net_calls": {}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}

    def fake_entry_points(group):
        if group == "dependency_scout.signature_providers":
            return [ep]
        return []

    with patch("importlib.metadata.entry_points", side_effect=fake_entry_points):
        with caplog.at_level("WARNING"):
            _load_plugins(acc)

    assert any("broken_provider" in r.message for r in caplog.records)


def test_load_plugins_no_entry_points():
    """No entry points registered — acc is unchanged."""
    acc = {"net_calls": {"existing": ["x"]}, "obfuscation": {}, "persistence": [],
           "suspicious_files": [], "suspicious_prefixes": [],
           "dangerous_binary": [], "install_hooks": [], "npm_install_scripts": []}

    with patch("importlib.metadata.entry_points", return_value=[]):
        _load_plugins(acc)

    assert acc["net_calls"] == {"existing": ["x"]}


# ---------------------------------------------------------------------------
# SignatureContribution defaults
# ---------------------------------------------------------------------------


def test_signature_contribution_defaults():
    contrib = SignatureContribution()
    assert contrib.net_call_patterns == {}
    assert contrib.obfuscation_patterns == {}
    assert contrib.persistence_patterns == []
    assert contrib.suspicious_package_files == []
    assert contrib.suspicious_package_prefixes == []
    assert contrib.dangerous_binary_suffixes == []
    assert contrib.install_hook_names == []
    assert contrib.npm_install_scripts == []
