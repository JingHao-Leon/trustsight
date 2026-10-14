"""Extracted from rules.py: _common."""

import logging

__all__ = ['MAX_RULE_LINE_BYTES', 'MAX_SCANNED_LINES', '_log']

_log = logging.getLogger(__name__)

MAX_RULE_LINE_BYTES = 8192

MAX_SCANNED_LINES = 20_000
