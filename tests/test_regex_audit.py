from scripts.regex_audit import audit_patterns


def test_shipped_regex_patterns_pass_the_adversarial_audit():
    audits = audit_patterns()
    assert audits
    failures = [audit for audit in audits if not audit.passed]
    assert failures == [], failures


def test_regex_audit_covers_configured_and_source_patterns():
    sources = {audit.source for audit in audit_patterns()}
    assert any(source.startswith("DEFAULT_RULES:") for source in sources)
    assert any(source.startswith("src/trustsight/") for source in sources)
    assert any(source.startswith("config-fragment:") for source in sources)


def test_inline_re_calls_are_audited():
    """A literal passed to ``re.search`` is compiled implicitly.

    The AST collector only saw ``re.compile(...)``, so every inline call was
    outside both the audit and the coverage gate.  The audit now collects
    them, and the whole point is that the coverage set says so.
    """
    from scripts.regex_audit import _inline_patterns, audit_patterns

    inline = {pattern for _source, pattern, _method in _inline_patterns()}
    audited = {audit.pattern for audit in audit_patterns()}
    assert inline
    assert inline <= audited


def test_an_inline_search_pattern_is_measured_where_it_searches():
    """Anchored calls are measured with ``match``; unanchored with search.

    ``\\w+\\+`` is the shape that separates the two: safe when anchored at
    position zero, quadratic when every start is tried.
    """
    from scripts.regex_audit import _anchored_risk

    import re

    compiled = re.compile(r"\w+\+")
    assert _anchored_risk(compiled, "match") < 0.02
