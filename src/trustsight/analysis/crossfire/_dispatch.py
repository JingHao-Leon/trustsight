"""Extracted from crossfire.py: _dispatch."""

from __future__ import annotations
from ._engine import crossfire_techniques

__all__ = ['X007_MIN_TECHNIQUES', '_NAMES', '_crossfire_findings']

_NAMES = {
    "X001": ("Encoded Payload Decoded And Executed", "CRITICAL"),
    "X002": ("Non-Literal Executable Name", "CRITICAL"),
    "X003": ("Obfuscated Command Argument", "HIGH"),
    "X004": ("Build Output Suppressed", "MEDIUM"),
    "X005": ("Home Reached By An Alternative Spelling", "HIGH"),
    "X006": ("Source Points Somewhere Unexpected", "HIGH"),
    "X008": ("Whitespace A Shell Does Not Split On", "MEDIUM"),
    "X009": ("Fetch Through An Uncatalogued Client", "CRITICAL"),
    "X010": ("Interpreter One-Liner Reaches The Network", "HIGH"),
    "X011": ("Package Manager Runs Fetched Code At Build Time", "HIGH"),
    "X012": ("Build Toolchain Redirected Into The Source Tree", "HIGH"),
    "X013": ("Fetch Redirected Or Trust Root Replaced", "HIGH"),
    "X014": ("Environment Variable Names Code To Run", "HIGH"),
    "X015": ("Work Scheduled To Run After The Build", "HIGH"),
    "X016": ("Fetch Piped Into An Unrecognised Consumer", "HIGH"),
    "X017": ("Tool Flag Or Builtin Carries A Command", "HIGH"),
    "X018": ("Interpreter One-Liner Assembles A Name", "HIGH"),
    "X019": ("Host Material Sent Or Packaged", "HIGH"),
    "X020": ("Recipe Writes The Build Steps The Engine Runs", "HIGH"),
    "X021": ("Executor Runs A File Chosen At Runtime", "HIGH"),
    "X022": ("Generated Config Handed To The Tool That Reads It", "HIGH"),
    "X023": ("Command Output Executed As A Script", "HIGH"),
    "X024": ("Indirect Sensitive Assignment", "HIGH"),
    "X025": ("Multi-Line Function Shadow", "HIGH"),
}

X007_MIN_TECHNIQUES = 2

def _crossfire_findings(diff_text, config, add, previous_diff: str = "",
                        previous_commit: str = "",
                        current_commit: str = "") -> None:
    """Emit X001-X006 and the X007 cluster.

    Each rule reports once per diff: a second `${A[0]}` tells the reader
    nothing the first did not, and counting occurrences would let a noisy
    recipe outscore a careful attack.  *previous_diff* is the immediately
    preceding recorded review of the same package, for X028.
    """
    techniques = crossfire_techniques(diff_text)

    for rule_id in ("X001", "X002", "X003", "X004", "X005", "X006", "X008",
                    "X009", "X010", "X011", "X012", "X013", "X014", "X015",
                    "X016", "X017", "X018", "X019", "X020", "X021", "X022",
                    "X023", "X024", "X025"):
        hits = techniques.get(rule_id)
        if not hits:
            continue
        line_no, shape, quoted = hits[0][0], hits[0][1], hits[0][2]
        name, severity = _NAMES[rule_id]
        add(rule_id, name, severity, "evasion",
            f"{shape}: {quoted}", line=line_no, shape=shape, body=quoted)

    if len(techniques) >= X007_MIN_TECHNIQUES:
        shapes = ", ".join(sorted(techniques))
        add("X007", "Multiple Evasion Techniques", "CRITICAL", "evasion",
            f"{len(techniques)} evasion techniques in one diff: {shapes}",
            line=None, count=len(techniques), techniques=shapes)

    # the refusal family. Deliberately outside the techniques
    # Dict above, so X007 keeps counting known techniques only.
    from ..refusals import refusal_findings

    refusal_findings(diff_text, config, add, previous_diff=previous_diff,
                     previous_commit=previous_commit,
                     current_commit=current_commit)
