"""Static install metadata across global and split-package scopes."""

import re

from ...line_lex import lex_lines
from ...recipedoc import _FUNCTION_OPEN_RE, parse_recipe
from ...tokenizer import split_lines


def declared_install_scripts(text: str) -> tuple[set[str], bool]:
    """Return resolved declarations and whether any declaration is unknown.

    makepkg sets pkgname to the split member while running package_<name>.
    Never resolve that scope using the pkgbase's flattened variable table.
    """
    globals_ = []
    depth = 0
    pending = False
    for lex in lex_lines(split_lines(text)):
        if not depth and _FUNCTION_OPEN_RE.match(lex.text.strip()):
            depth = lex.brace_delta
            pending = not lex.opens_brace
            continue
        if pending:
            if lex.opens_brace:
                depth = lex.brace_delta
                pending = False
            continue
        if depth:
            depth += lex.brace_delta
            continue
        globals_.append(lex.text)
    global_text = "\n".join(globals_)
    doc = parse_recipe(text)
    scopes = [global_text]
    # The tokenizer retains array and scalar tables separately: appending a
    # scalar does not erase the original pkgname array's first-member value.
    split_globals = re.sub(r"(?m)^\s*pkgname\s*=\s*\([^)]*\)", "", global_text)
    split_globals = re.sub(r"(?m)^\s*pkgname\s*=.*$", "", split_globals)
    scopes.extend(f"pkgname={name[8:]}\n" + split_globals + "\n" + body
                  for name, body in doc.functions.items()
                  if name.startswith("package_"))
    if len(scopes) > 1:
        scopes.pop(0)
    if "package" in doc.functions:
        scopes.append(global_text + "\n" + doc.functions["package"])
    declared = set()
    unknown = False
    for scope in scopes:
        parsed = parse_recipe(scope)
        value = parsed.scalars.get("install", "")
        has_assignment = re.search(r"(?m)^\s*install\s*=", scope)
        if "$" in value or (has_assignment and "install" not in parsed.scalars):
            unknown = True
        elif value:
            declared.add(value)
    return declared, unknown
