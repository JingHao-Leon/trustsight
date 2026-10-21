"""The CLI stderr handler is a terminal render boundary (A10).

Every log record reaches the same terminal as a review or inspect row.  A
maintainer name, URL, path or exception message can carry the input's bytes,
so the handler renders the message and the traceback inert without mutating
the record other handlers still need.
"""

import io
import logging
import sys

from trustsight.cli.app import _StderrHandler


def _emit(monkeypatch, record, fmt="%(message)s"):
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    handler = _StderrHandler()
    handler.setFormatter(logging.Formatter(fmt))
    handler.emit(record)
    return stream.getvalue()


def test_stderr_handler_cleans_the_message(monkeypatch):
    hostile = "evil\x1b[2J\x9b31m\u202eevil.example\nforged verdict"
    record = logging.LogRecord(
        "trustsight.test", logging.WARNING, __file__, 1, "%s",
        (hostile,), None)

    out = _emit(monkeypatch, record)

    assert "\x1b" not in out
    assert "\x9b" not in out
    assert "\u202e" not in out
    # The value's newline is flattened; only the handler terminator remains.
    assert out.count("\n") == 1
    assert out.endswith("\n")
    assert "evil.example" in out
    assert "forged verdict" in out


def test_stderr_handler_cleans_exception_text_but_keeps_layout(monkeypatch):
    try:
        raise ValueError("bad \x1b[2J\u202evalue")
    except ValueError:
        exc_info = sys.exc_info()
    record = logging.LogRecord(
        "trustsight.test", logging.ERROR, __file__, 1, "boom", (), exc_info)

    out = _emit(monkeypatch, record)

    assert "\x1b" not in out
    assert "\u202e" not in out
    assert "Traceback (most recent call last)" in out
    assert "ValueError" in out
    # Tracebacks are deliberately multi-line.
    assert out.count("\n") > 1


def test_stderr_handler_does_not_mutate_the_record(monkeypatch):
    hostile = "\x1b[2Jevil\nforged"
    record = logging.LogRecord(
        "trustsight.test", logging.WARNING, __file__, 1, "%s",
        (hostile,), None)

    _emit(monkeypatch, record)

    assert record.msg == "%s"
    assert record.args == (hostile,)
    # A later file/document handler still sees the original bytes.
    assert logging.Formatter("%(message)s").format(record) == hostile


def test_stderr_handler_never_dumps_a_record_on_format_failure(monkeypatch):
    class _BrokenFormatter(logging.Formatter):
        def format(self, record):
            raise ValueError("broken formatter")

    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    handler = _StderrHandler()
    handler.setFormatter(_BrokenFormatter())
    record = logging.LogRecord(
        "trustsight.test", logging.WARNING, __file__, 1, "%s",
        ("\x1b[2Jsecret",), None)

    handler.emit(record)

    out = stream.getvalue()
    assert "log record could not be formatted" in out
    assert "secret" not in out
    assert "\x1b" not in out
