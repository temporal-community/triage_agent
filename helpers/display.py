"""Shared ANSI color helpers and verdict display utilities for CLI scripts."""

from __future__ import annotations

import os

_G = "\033[32m"
_Y = "\033[33m"
_R = "\033[31m"
_C = "\033[36m"
_DIM = "\033[2m"
_B = "\033[1m"
_RST = "\033[0m"


def _g(s: str) -> str:
    return f"{_G}{s}{_RST}"


def _y(s: str) -> str:
    return f"{_Y}{s}{_RST}"


def _r(s: str) -> str:
    return f"{_R}{s}{_RST}"


def _dim(s: str) -> str:
    return f"{_DIM}{s}{_RST}"


def _bold(s: str) -> str:
    return f"{_B}{s}{_RST}"


def _info(s: str) -> str:
    return f"{_C}{s}{_RST}"


def _color_verdict(verdict: str) -> str:
    emoji = {"green": "🟢", "yellow": "🟡", "red": "🔴"}[verdict]
    color = {"green": _G, "yellow": _Y, "red": _R}[verdict]
    return f"{emoji} {color}{_B}{verdict.upper()}{_RST}"


def _merge_rec_label(merge_rec: str | None) -> str:
    if merge_rec == "merge":
        return f"  {_G}⚡ merge recommended{_RST}"
    if merge_rec == "hold":
        return f"  {_Y}⏸ hold recommended{_RST}"
    return ""


def _clf_name() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "Claude"
    if os.environ.get("OPENAI_API_KEY"):
        return "OpenAI"
    if os.environ.get("OLLAMA_HOST"):
        return "Ollama"
    if os.environ.get("CLASSIFIER"):
        return os.environ["CLASSIFIER"]
    return None
