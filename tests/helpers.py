"""Shared test helpers — plain functions, not pytest fixtures."""

from __future__ import annotations

import io
import tarfile
import zipfile


def make_tar_gz(files: dict[str, str], top_dir: str = "pkg-1.0.0") -> bytes:
    """Build an in-memory .tar.gz archive.

    *files* maps relative paths (inside *top_dir*) to file contents.
    The archive mimics a real sdist: each member is prefixed with *top_dir/*.
    """
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


def make_zip(files: dict[str, str]) -> bytes:
    """Build an in-memory .zip archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf.read()
