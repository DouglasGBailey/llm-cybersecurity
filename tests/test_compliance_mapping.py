from src.compliance_mapping import COMPLIANCE_MAP, compliance_tags_for


def test_known_type_returns_expected_tags():
    tags = compliance_tags_for("missing-security-headers")
    assert tags
    assert any(t["framework"] == "OWASP Top 10 2021" for t in tags)


def test_unknown_type_returns_empty_list():
    assert compliance_tags_for("some-made-up-type") == []


def test_pure_info_types_are_intentionally_unmapped():
    for ftype in ("dns-resolution", "page-title", "whois-registrar", "tool-unavailable"):
        assert compliance_tags_for(ftype) == []


def test_all_tags_are_well_formed():
    for ftype, tags in COMPLIANCE_MAP.items():
        assert tags, f"{ftype} has an empty tag list -- remove the entry instead"
        for tag in tags:
            assert set(tag.keys()) == {"framework", "control"}
            assert tag["framework"]
            assert tag["control"]


def test_llm_probe_failed_maps_to_llm_framework():
    tags = compliance_tags_for("llm-probe-failed")
    assert any(t["framework"] == "OWASP Top 10 for LLM Applications" for t in tags)


def test_tls_expired_maps_to_crypto_failures_and_pci():
    tags = compliance_tags_for("tls-certificate-expired")
    frameworks = {t["framework"] for t in tags}
    assert "OWASP Top 10 2021" in frameworks
    assert "PCI DSS 4.0" in frameworks
