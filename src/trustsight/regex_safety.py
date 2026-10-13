"""Dependency-free safeguards for regexes applied to hostile text."""

from __future__ import annotations

import re
import time
import warnings

BACKTRACK_REPS = 22
BACKTRACK_BUDGET_S = 0.02

#: Length of the long-form probes.
#:
#: The short probes above are 22 characters, which is tuned for
#: *exponential* backtracking: 2^22 is millions of steps and shows up
#: instantly. Polynomial cost is invisible there - 22 squared is 484 steps -
#: and rules run against lines up to `rules.MAX_RULE_LINE_BYTES` (8192),
#: where the same pattern costs 67 million. Three shipped patterns were
#: quadratic and every one of them passed the short probes: a version
#: matcher took 3.2 seconds on one line, and a `sudo` matcher 1.1 seconds.
#:
#: 2048 is the compromise. Quadratic behaviour is plainly visible (4.2M
#: steps, tens of milliseconds) while a linear pattern stays in the
#: microseconds, and probing every pattern at the full 8192 would put real
#: time on the startup path for no extra signal.
LONG_PROBE_LEN = 4096

BACKTRACK_PROBES = (
    "a" * BACKTRACK_REPS + "!",
    "a" * BACKTRACK_REPS,
    " " * BACKTRACK_REPS + "!",
    "https://" + "a." * (BACKTRACK_REPS // 2) + "com",
    "curl " + "|" * BACKTRACK_REPS,
    "/" * BACKTRACK_REPS + "!",
    # A dotted name with no scheme in front of it. The URL probe above
    # cannot reach an anchored host pattern like ``^(\\w+\\.)+\\w+$``,
    # because ``https://`` fails the anchor at position 0 and the match
    # ends before any backtracking starts. Host- and module-shaped names
    # are among the most common things matched here.
    "a." * (BACKTRACK_REPS // 2) + "com",
    # Digits. Nothing above contains one, so every pattern driven by
    # ``\\d`` or ``[0-9]`` used to be probed with input it cannot match,
    # and scored a risk of exactly zero.
    "1" * BACKTRACK_REPS + "!",
    "1," * (BACKTRACK_REPS // 2) + "!",
    # Long forms. A pattern that is merely quadratic costs nothing
    # measurable at 22 characters and seconds at a full line.
    "a" * LONG_PROBE_LEN + "!",
    " " * LONG_PROBE_LEN + "!",
    "1" * LONG_PROBE_LEN + "!",
    "a." * (LONG_PROBE_LEN // 2) + "!",
    "a " * (LONG_PROBE_LEN // 2) + "!",
    "/" * LONG_PROBE_LEN + "!",
)

#: Representative characters for the classes a pattern can be built from.
#: A probe only exercises a pattern if it is drawn from that pattern's own
#: alphabet, which is why the fixed set above cannot be sufficient on its
#: own however long it grows.
_CLASS_SAMPLES = (
    (r"\d", "1"), (r"\w", "a"), (r"\s", " "), (r"\S", "a"),
    (r"0-9", "1"), (r"a-z", "a"), (r"A-Z", "A"), (r"A-Za-z", "a"),
)

_CHAR_CLASS_RE = re.compile(r"\[(\^?)((?:[^\]\\]|\\.){1,64})\]")
_ESCAPE_RE = re.compile(r"\\([dwsS])")

#: Syntax that must not be mined for literals. A ``:`` from ``(?:``, a digit
#: from ``{1,64}`` or a ``^`` from a class body is punctuation the engine
#: consumes as grammar, and probing with it means probing with a character
#: the pattern cannot match - the same "wrong alphabet" failure the derived
#: probes exist to remove.
_SYNTAX_RE = re.compile(
    r"\[\^?(?:[^\]\\]|\\.){0,64}\]"     # class bodies: mined separately
    r"|\((?:\?(?:P?<[^>]{0,32}>|[:=!#]|<[=!]|[aiLmsux]{1,6}[:)]))?"  # group openers
    r"|\{\d{0,8}(?:,\d{0,8})?\}"        # counted quantifiers
    r"|\\[dwsSbBAZzGnrtfv0-9]"          # class escapes and non-literal escapes
)

#: Characters the engine reads as grammar rather than input.
_METACHARACTERS = frozenset(".^$*+?()[]{}|\\")

#: Probed when a pattern yields no alphabet of its own. It is a fallback,
#: not a measurement: a pattern whose alphabet cannot be derived is unknown
#: rather than safe, so the fallback is several characters wide instead of
#: one, and ``growth_ratio`` says so where it uses it.
_FALLBACK_ALPHABET = ("a", "1", " ", "/")

#: Distinct alphabets probed per pattern, and probe shapes per alphabet.
#: Both are capped because this runs at rule-compile time.
_MAX_DERIVED_ALPHABETS = 4



#: Tried in order against a character class to find one it accepts. Broad
#: enough that a negated class - which excludes a few characters and admits
#: everything else - is answered by the first or second candidate.
_CLASS_CANDIDATES = ("a", "1", " ", "/", "-", "_", ".", ":", "x")


def _class_representative(body: str, negated: bool) -> str:
    r"""One character the class ``[body]`` accepts, or "" if none is found.

    Asked of the compiled class rather than inferred from its text, because
    inference read a *negated* class as a positive one. ``[^\s]+`` derived
    ``" "`` - the single character it cannot match - and ``[^0-9]+`` derived
    ``"1"``. A pattern probed with input it cannot consume measures zero
    time, and zero is indistinguishable from fast, so every pattern driven
    by a negated class was scored safe without ever being measured.

    That is the same failure that let a quadratic ``/+$`` ship: the
    alphabet, not the timing, is what the check rests on.
    """
    try:
        with warnings.catch_warnings():
            # A body holding `[` - `[[:space:]]`, `[\[\]]` - warns about a
            # nested set when re-wrapped. The class means the same thing
            # either way for the only question asked here, which is whether
            # some character matches it.
            warnings.simplefilter("ignore", FutureWarning)
            compiled = re.compile(f"[{'^' if negated else ''}{body}]")
    except re.error:
        return ""
    for candidate in _CLASS_CANDIDATES:
        if compiled.match(candidate):
            return candidate
    # No ASCII candidate matched, so the class is non-ASCII: read a
    # character out of the class's own text. R013 is the case that matters
    # - it is FATAL, its body is `\u202A-\u202E` and friends, and every
    # fixed probe in this module is ASCII, so both its risk and its growth
    # were measured against input it cannot match. A FATAL rule whose cost
    # is unmeasured is exactly the gap this module exists to close.
    for candidate in _codepoints_in(body):
        if compiled.match(candidate):
            return candidate
    return ""


_ESCAPED_CODEPOINT_RE = re.compile(
    r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})"
)

#: Single-letter escapes, which name a character without spelling its
#: codepoint.  Without these `[\t\n\r\f\v]+` derived nothing: the scan
#: for literals sees `t`, `n`, `r` - the letters, not the controls they
#: stand for - and none of them matches the class.
_ESCAPE_LETTERS = {
    "t": "\t", "n": "\n", "r": "\r", "f": "\f", "v": "\v",
    "a": "\a", "b": "\b", "0": "\0", "e": "\x1b",
}


def _codepoints_in(body: str) -> list[str]:
    """Characters named by a class body, escapes decoded, in order.

    A range start is enough: ``[\u202A-\u202E]`` is exercised by
    ``\u202A``. Only a bounded prefix is read, because the body is
    attacker-authored text like everything else here.
    """
    out: list[str] = []
    index = 0
    while index < len(body[:512]) - 1:
        if body[index] == "\\" and body[index + 1] in _ESCAPE_LETTERS:
            char = _ESCAPE_LETTERS[body[index + 1]]
            if char not in out:
                out.append(char)
            index += 2
            continue
        index += 1
    for match in _ESCAPED_CODEPOINT_RE.finditer(body[:512]):
        digits = match.group(1) or match.group(2) or match.group(3)
        try:
            out.append(chr(int(digits, 16)))
        except (ValueError, OverflowError):
            continue
        if len(out) >= 8:
            return out
    for char in body[:512]:
        if char not in "\\-^[]" and char not in out:
            out.append(char)
            if len(out) >= 8:
                break
    return out


def _representatives(pattern: str) -> list[str]:
    """Characters this pattern can actually consume, longest-repeat first.

    Deriving the probe alphabet from the pattern is what makes the check
    general. A fixed probe list is a list of the attacks somebody thought
    of, and the classes it omits score zero risk rather than unknown risk.
    """
    found: list[str] = []

    def add(char: str) -> None:
        if char and char not in found:
            found.append(char)

    # Class bodies are removed first: an escape *inside* a class is the
    # class's business, and reading `\s` out of `[^\s]` added a space -
    # the one character that class excludes.
    outside_classes = _CHAR_CLASS_RE.sub(" ", pattern)
    for escape in _ESCAPE_RE.findall(outside_classes):
        for token, sample in _CLASS_SAMPLES:
            if token == "\\" + escape:
                add(sample)

    for negation, body in _CHAR_CLASS_RE.findall(pattern):
        add(_class_representative(body, bool(negation)))

    # Literals in the pattern itself, for shapes like ``(x|x)*`` or ``/+$``
    # where no class appears at all.
    #
    # This used to take the first *alphanumeric* character and stop. A
    # pattern whose only consumable literal is punctuation - ``/+$`` is the
    # reported one - therefore derived no alphabet at all, fell back to
    # probing with ``a``, which ``/`` can never match, and measured zero on
    # every probe. Zero is then indistinguishable from fast, so a quadratic
    # pattern scored safe. Punctuation is input like any other character;
    # what it must not be is *syntax*, which is what ``_SYNTAX_RE`` strips
    # before this scan.
    consumable = _SYNTAX_RE.sub(" ", pattern)
    escaped = False
    for char in consumable:
        if escaped:
            # ``\.`` and friends: the escape made a metacharacter literal.
            add(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in _METACHARACTERS or char.isspace():
            continue
        add(char)

    return found[:_MAX_DERIVED_ALPHABETS]


def derived_probes(pattern: str) -> tuple[str, ...]:
    """Attack strings built from *pattern*'s own alphabet.

    Each alphabet is probed short and long: short finds exponential
    backtracking, long finds polynomial cost that only appears at the line
    lengths these patterns actually see.
    """
    probes: list[str] = []
    half = BACKTRACK_REPS // 2
    long_half = LONG_PROBE_LEN // 2
    for char in _representatives(pattern):
        probes.append(char * BACKTRACK_REPS + "!")
        probes.append((char + ".") * half + "!")
        probes.append((char + " ") * half + "!")
        probes.append(char * LONG_PROBE_LEN + "!")
        probes.append((char + " ") * long_half + "!")
    return tuple(probes)


# Restrict the structural check to the classic ambiguous single-atom forms.
# Broader nested-quantifier heuristics reject safe patterns whose inner and
# outer character classes are disjoint, such as ``(?:-\S+\s+)*``.
_NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:\?:)?(?:[A-Za-z0-9.]|\.\*|\.\+|\\[wds])[*+]\)\s*[*+{]"
)

# A quantified character class inside a quantified group: ``([0-9]+)+``.
# The rule above only covers single atoms and escapes, so a class spelled
# out longhand went structurally unnoticed.
_NESTED_CLASS_QUANTIFIER_RE = re.compile(
    r"\((?:\?:)?\[\^?(?:[^\]\\]|\\.){1,64}\][*+]\)\s*[*+{]"
)

# An alternation whose branches match the same text, under a quantifier:
# ``(x|x)*``. Both branches are tried at every position, so the engine has
# two ways to consume each character and the search space doubles.
_AMBIGUOUS_ALTERNATION_RE = re.compile(
    r"\((?:\?:)?([^()|]{1,32})\|([^()|]{1,32})\)\s*[*+{]"
)


def _branches_overlap(left: str, right: str) -> bool:
    """Whether two alternation branches match exactly the same input.

    Identical branches only. A *prefix* relationship such as ``(a|ab)+``
    is the other textbook ambiguity, and it was rejected here until it was
    measured: under both attack shapes it is linear in CPython, so
    refusing it bought nothing. It is not a free guess either - a refused
    pattern does not raise, it returns None and the rule quietly stops
    matching, so a false refusal is a hole rather than an inconvenience.
    """
    return left == right and bool(left)


#: Below this growth the 4096-character measurement is trusted outright:
#: no superlinear shape has measured this low in the corpus, and escalating
#: every quiet pattern would put the longer probe on the startup path.
_BORDERLINE_GROWTH = 3.0

#: The refusal threshold at the four-times-longer baseline. Four times the
#: input costs four times the time when linear and sixteen when quadratic,
#: so 8, their geometric midpoint, is the balanced boundary between the two
#: hypotheses. The shipped linear patterns measure 3.8 to 4.4 there and the
#: quadratic matcher 13 to 25, so the boundary sits about twice away from
#: either side.
_ESCALATED_GROWTH = 8.0


def is_superlinear(compiled: re.Pattern) -> bool:
    """Whether *compiled* costs more than linearly in its input length.

    The flakiness this replaced lived entirely in `_growth`, not here: a
    fast linear matcher's short probe is tens of microseconds, so a single
    contended long reading just over the floor divided by it produced a
    spurious ratio of 6 to 27 and the shipped-pattern audit refused a linear
    pattern as quadratic.  Flooring the ratio's divisor (see
    :data:`_GROWTH_FLOOR_S`) bounds that quotient by ``long_med / floor``, so
    the noisy reading is no longer amplified into a verdict and the decision
    can stay a single clean measurement.

    Re-measuring and taking the minimum, the obvious alternative, is unsafe
    in the other direction: contention inflates the *short* probe as readily
    as the long one, and a retry whose short reading spiked drops a genuine
    quadratic's ratio below the threshold, so the min hides a real pattern.

    A *borderline* ratio escalates to a four-times longer baseline instead
    of being trusted.  There is no separate "immediate refuse" band above it:
    the same escalation decides every suspicious reading.  A single 4096-char
    ratio is what a starved scheduler inflates - a linear matcher's long
    probe can spike above ten while short stays near the floor - and refusing
    on that one reading is exactly the flake.  At four times the length the
    two hypotheses separate cleanly (the quadratics measure ~15, a fast
    linear matcher ~2), so the escalated ratio is the only one trusted.  It
    costs seconds for a genuinely quadratic pattern, which is rare and is
    being refused anyway.
    """
    ratio = growth_ratio(compiled)
    if ratio <= _BORDERLINE_GROWTH:
        return False
    return _growth(compiled, LONG_PROBE_LEN * 4)[0] > _ESCALATED_GROWTH


def has_nested_quantifier(pattern: str) -> bool:
    """Conservatively detect nested quantified groups."""
    if _NESTED_QUANTIFIER_RE.search(pattern):
        return True
    if _NESTED_CLASS_QUANTIFIER_RE.search(pattern):
        return True
    for left, right in _AMBIGUOUS_ALTERNATION_RE.findall(pattern):
        if _branches_overlap(left, right):
            return True
    return False


#: Below this, a measurement is noise rather than signal.  It floors the long
#: median (a pattern too fast to measure is fast enough) and caps the divisor
#: of the growth ratio, so a contended reading cannot be divided by a
#: microsecond-scale short probe into a spurious quadratic verdict.
_GROWTH_FLOOR_S = 0.001


def _time_search(compiled: re.Pattern, text: str) -> float:
    """CPU seconds for one search.

    `time.process_time` measures time the process actually ran, not wall
    time.  A regex costs CPU, never I/O, so the only thing wall time adds is
    the scheduler's opinion: on a machine building the package beside a
    5,700-test suite a wall-clock reading is inflated by every deschedule,
    which is what made the shipped-pattern audit fail intermittently on a
    linear pattern and pass on the next identical run.  Process CPU time is
    immune to being starved of the CPU and to background load; only genuine
    work moves it.
    """
    start = time.process_time()
    try:
        compiled.search(text)
    except (RecursionError, MemoryError):
        return BACKTRACK_BUDGET_S * 100
    return time.process_time() - start


def _growth(compiled: re.Pattern,
            long_len: int = LONG_PROBE_LEN) -> tuple[float, float]:
    """``(worst growth ratio, worst long-probe seconds)`` for *compiled*.

    The ratio is the shape signal; the absolute cost at the longer length
    is the speed-independent one. Both come from one set of measurements.
    """
    worst_ratio = 0.0
    worst_long = 0.0
    # ``or _FALLBACK_ALPHABET``: a pattern with no derivable alphabet has
    # not been measured, and an unmeasured pattern is unknown rather than
    # safe. Several characters are tried instead of one so the fallback has
    # some chance of being input the pattern can actually consume.
    alphabets = _representatives(compiled.pattern) or list(_FALLBACK_ALPHABET)
    for char in alphabets[:2]:
        short_text = char * (long_len // 4) + "!"
        long_text = char * long_len + "!"
        # Three measurements each; median filters out scheduler noise.
        shorts = sorted(_time_search(compiled, short_text) for _ in range(3))
        longs = sorted(_time_search(compiled, long_text) for _ in range(3))
        short_med = shorts[1]  # median
        long_med = longs[1]    # median
        worst_long = max(worst_long, long_med)
        if long_med < _GROWTH_FLOOR_S:
            continue
        # The numerator is floored, so only a pattern genuinely slower than
        # the floor at the long length can clear the threshold; the divisor
        # is floored too, which bounds any ratio by `long_med / floor`.  That
        # is what removes the flake: a fast linear matcher's short probe is
        # tens of microseconds, and a single contended long reading just over
        # the floor divided by it produced a spurious ratio of 6 to 27, which
        # the shipped-pattern audit then refused as quadratic.  Flooring the
        # *short median itself* and skipping when it is below is wrong - it
        # hides a genuine quadratic whose short probe sits at the floor (the
        # `(-?\\d+,)+;` matcher measures ~1 ms there).
        worst_ratio = max(worst_ratio, long_med / max(short_med, _GROWTH_FLOOR_S))
    return worst_ratio, worst_long


def growth_ratio(compiled: re.Pattern,
                 long_len: int = LONG_PROBE_LEN) -> float:
    """How much slower *compiled* gets when its input grows four times.

    The absolute budget alone misses a quadratic pattern with a small
    constant: it is genuinely quadratic, and genuinely under the budget at
    the probe length, so it passes and then costs seconds at a full line.
    Shape is the more durable signal, and measuring it needs two lengths.

    Each length is measured three times and the median is taken.  The
    median is resistant to scheduler noise on loaded machines, unlike the
    minimum which can still be inflated when both measurements land in a
    noisy window.
    """
    return _growth(compiled, long_len)[0]


def backtracking_risk(compiled: re.Pattern) -> float:
    """Return the worst bounded-probe match time in seconds.

    Probes are the fixed set plus a set derived from the pattern, because
    a probe drawn from the wrong alphabet reports zero rather than safe.
    Measured as process CPU time, not wall time: a match costs CPU and never
    I/O, so wall time only adds the scheduler's opinion, and a pattern on a
    loaded machine then reads as over budget when it is not.
    """
    worst = 0.0
    probes = BACKTRACK_PROBES + derived_probes(compiled.pattern)
    for probe in probes:
        start = time.process_time()
        try:
            compiled.search(probe)
        except (RecursionError, MemoryError):
            return BACKTRACK_BUDGET_S * 100
        elapsed = time.process_time() - start
        worst = max(worst, elapsed)
        # A pattern already over budget needs no further probing, and the
        # remaining probes on a catastrophic pattern are the expensive part.
        if worst > BACKTRACK_BUDGET_S:
            return worst
    return worst
