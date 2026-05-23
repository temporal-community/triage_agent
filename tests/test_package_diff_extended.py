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

import activities.package_diff as pkg_diff_module
from activities.package_diff import (
    _build_diff,
    _extract_and_diff,
    _get_file_map,
    _is_noise,
    _safe_zip_extractall,
    compute,
)

PYPI_BASE = "https://pypi.org/pypi"


# ---------------------------------------------------------------------------
# Helpers (reuse + extend from existing test_package_diff.py)
# ---------------------------------------------------------------------------

def _make_tar_gz(files: dict[str, str], top_dir: str = "pkg-1.0.0") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel_path, content in files.items():
            member_name = f"{top_dir}/{rel_path}"
            data = content.encode()
            info = tarfile.TarInfo(name=member_name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf.read()


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf.read()


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
    with patch.object(pkg_diff_module, "MAX_EXTRACT_BYTES", 5):
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
    result = _build_diff(old, new)
    assert result == "[no significant changes detected]"


def test_build_diff_other_changed_file(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/utils.py": "x = 1\n"})
    new = _write_files(tmp_path / "new", {"pkg/utils.py": "x = 2\n"})
    result = _build_diff(old, new)
    assert "CHANGED (other)" in result
    assert "pkg/utils.py" in result


def test_build_diff_dangerous_new_binary(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/__init__.py": "x=1\n"})
    new = _write_files(tmp_path / "new", {
        "pkg/__init__.py": "x=1\n",
        "pkg/_speedups.so": b"\x7fELF",
    })
    result = _build_diff(old, new)
    assert "DANGEROUS BINARY" in result
    assert "_speedups.so" in result
    assert "NEW:" in result


def test_build_diff_dangerous_changed_binary(tmp_path):
    old = _write_files(tmp_path / "old", {"pkg/_ext.so": b"\x7fELF old"})
    new = _write_files(tmp_path / "new", {"pkg/_ext.so": b"\x7fELF new"})
    result = _build_diff(old, new)
    assert "DANGEROUS BINARY" in result
    assert "MODIFIED:" in result
    assert "_ext.so" in result


def test_build_diff_dangerous_changed_binary_unchanged_hash_not_reported(tmp_path):
    content = b"\x7fELF identical"
    old = _write_files(tmp_path / "old", {"pkg/_ext.so": content})
    new = _write_files(tmp_path / "new", {"pkg/_ext.so": content})
    result = _build_diff(old, new)
    assert result == "[no significant changes detected]"


def test_build_diff_truncated_when_large(tmp_path):
    # __init__.py is high-signal → full unified diff is included → can exceed 100KB
    large_old = "\n".join(f"line_old_{i} = {i}" for i in range(15_000))
    large_new = "\n".join(f"line_new_{i} = {i}" for i in range(15_000))
    old = _write_files(tmp_path / "old", {"__init__.py": large_old})
    new = _write_files(tmp_path / "new", {"__init__.py": large_new})
    result = _build_diff(old, new)
    assert "truncated" in result
    assert "100KB" in result


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
    result = _extract_and_diff(b"not a real archive", "bad.tar.gz", b"also bad", "bad2.tar.gz")
    assert result.startswith("[extraction error:")


def test_extract_and_diff_unsupported_format_returns_error_string():
    result = _extract_and_diff(b"data", "pkg.rpm", b"data", "pkg2.rpm")
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
    from activities.package_diff import _validate_archive_url
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="only https"):
        _validate_archive_url("http://files.pythonhosted.org/pkg-1.0.0.tar.gz")


def test_validate_archive_url_rejects_untrusted_host():
    from activities.package_diff import _validate_archive_url
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="Untrusted archive host"):
        _validate_archive_url("https://evil.example.com/pkg-1.0.0.tar.gz")


def test_validate_archive_url_rejects_ssrf_metadata_endpoint():
    from activities.package_diff import _validate_archive_url
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="Untrusted archive host"):
        _validate_archive_url("https://169.254.169.254/latest/meta-data/iam/security-credentials/")


def test_validate_archive_url_rejects_localhost():
    from activities.package_diff import _validate_archive_url
    from temporalio.exceptions import ApplicationError
    with pytest.raises(ApplicationError, match="Untrusted archive host"):
        _validate_archive_url("https://localhost/internal-api")


def test_validate_archive_url_accepts_pythonhosted():
    from activities.package_diff import _validate_archive_url
    _validate_archive_url("https://files.pythonhosted.org/packages/pkg-1.0.0.tar.gz")


def test_validate_archive_url_accepts_npm_registry():
    from activities.package_diff import _validate_archive_url
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
