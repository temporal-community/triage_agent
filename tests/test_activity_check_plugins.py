"""Tests for _discover_activity_check_plugins in worker.py.

Covers the dependency_scout.activity_checks entry-point discovery path:
- A properly @activity.defn-decorated function is picked up and registered.
- A plain async function (no @activity.defn) is skipped with a warning.
- A load failure (broken entry point) is skipped with a warning.
"""

import logging
from unittest.mock import MagicMock, patch

from temporalio import activity

from worker import _discover_activity_check_plugins


@activity.defn(name="test.activity_check_plugins.good_activity")
async def _good_activity(ctx):
    return {"result": "ok"}


async def _plain_async_fn(ctx):
    """Plain async function — NOT decorated with @activity.defn."""
    return {"result": "ok"}


def test_discover_picks_up_properly_decorated_activity():
    """A @activity.defn-decorated function is returned by the discovery function."""
    ep = MagicMock()
    ep.name = "good_check"
    ep.load.return_value = _good_activity

    with patch("importlib.metadata.entry_points", return_value=[ep]):
        result = _discover_activity_check_plugins()

    assert _good_activity in result


def test_discover_skips_plain_async_function(caplog):
    """A plain async function without @activity.defn is skipped with a warning."""
    ep = MagicMock()
    ep.name = "plain_check"
    ep.load.return_value = _plain_async_fn

    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with caplog.at_level(logging.WARNING):
            result = _discover_activity_check_plugins()

    assert result == []
    assert "plain_check" in caplog.text
    assert "@activity.defn" in caplog.text


def test_discover_skips_non_callable(caplog):
    """A non-callable entry point value is skipped with a warning."""
    ep = MagicMock()
    ep.name = "not_a_function"
    ep.load.return_value = "just a string, not callable... wait strings are callable-ish"

    # Use an integer — definitely not callable
    ep.load.return_value = 42

    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with caplog.at_level(logging.WARNING):
            result = _discover_activity_check_plugins()

    assert result == []
    assert "not_a_function" in caplog.text
    assert "not callable" in caplog.text


def test_discover_skips_load_failure(caplog):
    """A broken entry point (load raises) is skipped with a warning."""
    ep = MagicMock()
    ep.name = "broken_plugin"
    ep.load.side_effect = ImportError("module not found")

    with patch("importlib.metadata.entry_points", return_value=[ep]):
        with caplog.at_level(logging.WARNING):
            result = _discover_activity_check_plugins()

    assert result == []
    assert "broken_plugin" in caplog.text


def test_discover_deduplicates_same_function():
    """The same function registered twice is only included once."""
    ep1 = MagicMock()
    ep1.name = "check_a"
    ep1.load.return_value = _good_activity

    ep2 = MagicMock()
    ep2.name = "check_b"
    ep2.load.return_value = _good_activity  # same function object

    with patch("importlib.metadata.entry_points", return_value=[ep1, ep2]):
        result = _discover_activity_check_plugins()

    assert result.count(_good_activity) == 1


def test_discover_returns_empty_when_no_entry_points():
    """Returns an empty list when no dependency_scout.activity_checks plugins are installed."""
    with patch("importlib.metadata.entry_points", return_value=[]):
        result = _discover_activity_check_plugins()

    assert result == []
