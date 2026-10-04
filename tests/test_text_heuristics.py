from tools.text_url_tool import _check_url_heuristics, _extract_urls


def test_extracts_bare_domain_from_telegram_style_message():
    assert _extract_urls("Kartangiz bloklandi: kap1talbank.uz ga kiring!") == ["kap1talbank.uz"]


def test_detects_typo_squatting_without_url_scheme():
    findings = _check_url_heuristics("kap1talbank.uz")
    assert any("Typo-squatting" in finding for finding in findings)


def test_detects_punycode_in_subdomain():
    findings = _check_url_heuristics("https://xn--payme-9db.uz/login")
    assert any("Punycode" in finding for finding in findings)
