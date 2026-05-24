"""
Tests for activities/package_diff.py.

HTTP is mocked with respx. In-memory tar.gz archives are built with tarfile +
io.BytesIO. ActivityEnvironment provides the Temporal activity context.
"""

from __future__ import annotations

import httpx
import respx
from temporalio.testing import ActivityEnvironment

from activities.package_diff import compute
from tests.helpers import make_tar_gz as _make_tar_gz

PYPI_BASE = "https://pypi.org/pypi"


def _pypi_json(package: str, version: str, sdist_url: str | None = None) -> dict:
    """Minimal PyPI JSON API response for one version."""
    urls = []
    if sdist_url:
        urls.append(
            {
                "packagetype": "sdist",
                "url": sdist_url,
                "filename": f"{package}-{version}.tar.gz",
            }
        )
    return {
        "info": {"name": package, "version": version},
        "urls": urls,
    }


def _mock_pypi_and_archive(
    package: str,
    old_version: str,
    new_version: str,
    old_files: dict[str, str],
    new_files: dict[str, str],
) -> None:
    """Register respx routes for both PyPI JSON endpoints and both sdist downloads."""
    old_sdist_url = f"https://files.pythonhosted.org/{package}-{old_version}.tar.gz"
    new_sdist_url = f"https://files.pythonhosted.org/{package}-{new_version}.tar.gz"

    respx.get(f"{PYPI_BASE}/{package}/{old_version}/json").mock(
        return_value=httpx.Response(200, json=_pypi_json(package, old_version, old_sdist_url))
    )
    respx.get(f"{PYPI_BASE}/{package}/{new_version}/json").mock(
        return_value=httpx.Response(200, json=_pypi_json(package, new_version, new_sdist_url))
    )
    respx.get(old_sdist_url).mock(
        return_value=httpx.Response(
            200,
            content=_make_tar_gz(old_files, top_dir=f"{package}-{old_version}"),
        )
    )
    respx.get(new_sdist_url).mock(
        return_value=httpx.Response(
            200,
            content=_make_tar_gz(new_files, top_dir=f"{package}-{new_version}"),
        )
    )


# ---------------------------------------------------------------------------
# Test 1: basic diff — one changed file, one new file
# ---------------------------------------------------------------------------


@respx.mock
async def test_basic_diff_changed_and_new_file():
    old_files = {
        "mypkg/__init__.py": "version = '1.0.0'\n",
        "mypkg/helpers.py": "def greet():\n    return 'hello'\n",
    }
    new_files = {
        "mypkg/__init__.py": "version = '1.1.0'\n",
        "mypkg/helpers.py": "def greet():\n    return 'hello'\n",  # unchanged
        "mypkg/utils.py": "def util():\n    pass\n",  # new file
    }

    _mock_pypi_and_archive("mypkg", "1.0.0", "1.1.0", old_files, new_files)

    env = ActivityEnvironment()
    result = await env.run(compute, "pip", "mypkg", "1.0.0", "1.1.0")

    assert result.diff_size_bytes > 0
    assert "NEW FILES" in result.diff_summary
    assert "mypkg/utils.py" in result.diff_summary


# ---------------------------------------------------------------------------
# Test 2: no sdist available (PyPI returns empty urls list)
# ---------------------------------------------------------------------------


@respx.mock
async def test_no_sdist_available_returns_graceful_stub():
    respx.get(f"{PYPI_BASE}/nosrc/1.0.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("nosrc", "1.0.0", sdist_url=None))
    )
    respx.get(f"{PYPI_BASE}/nosrc/1.1.0/json").mock(
        return_value=httpx.Response(200, json=_pypi_json("nosrc", "1.1.0", sdist_url=None))
    )

    env = ActivityEnvironment()
    result = await env.run(compute, "pip", "nosrc", "1.0.0", "1.1.0")

    assert result.diff_summary == "[sdist not available]"
    assert result.diff_size_bytes == 0


# ---------------------------------------------------------------------------
# Test 3: high-signal file (setup.py) changed → appears in correct section
# ---------------------------------------------------------------------------


@respx.mock
async def test_high_signal_setup_py_changed():
    old_files = {
        "setup.py": "from setuptools import setup\nsetup(name='pkg', version='1.0')\n",
        "pkg/__init__.py": "__version__ = '1.0'\n",
    }
    new_files = {
        "setup.py": (
            "from setuptools import setup\n"
            "setup(name='pkg', version='1.1', install_requires=['requests'])\n"
        ),
        "pkg/__init__.py": "__version__ = '1.0'\n",
    }

    _mock_pypi_and_archive("hspkg", "1.0.0", "1.1.0", old_files, new_files)

    env = ActivityEnvironment()
    result = await env.run(compute, "pip", "hspkg", "1.0.0", "1.1.0")

    assert "CHANGED (high-signal)" in result.diff_summary
    assert "setup.py" in result.diff_summary
    assert "install_requires" in result.diff_summary


# ---------------------------------------------------------------------------
# Test 4: new file added → appears in NEW FILES section
# ---------------------------------------------------------------------------


@respx.mock
async def test_new_file_appears_in_new_files_section():
    old_files = {
        "pkg/__init__.py": "x = 1\n",
    }
    new_files = {
        "pkg/__init__.py": "x = 1\n",
        "pkg/postinstall.js": "console.log('postinstall');\n",  # new file, also high-signal name
    }

    _mock_pypi_and_archive("newfilepkg", "2.0.0", "2.1.0", old_files, new_files)

    env = ActivityEnvironment()
    result = await env.run(compute, "pip", "newfilepkg", "2.0.0", "2.1.0")

    assert "NEW FILES" in result.diff_summary
    assert "postinstall.js" in result.diff_summary
