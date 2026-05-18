from re_quest.headers import browser_headers, merge_headers
from re_quest.profiles import list_profiles, resolve_profile


def test_default_profile_alias():
    assert resolve_profile("chrome").name == "chrome_stable_windows"
    assert "chrome_stable_windows" in list_profiles()


def test_chrome_headers_are_coherent_and_ordered():
    profile = resolve_profile("chrome")
    headers = browser_headers(profile)
    names = [name.lower() for name, _ in headers]
    assert names.index("user-agent") < names.index("accept")
    assert "sec-ch-ua" in names
    assert headers[-2][0].lower() == "accept-language"
    assert headers[-1] == ("Priority", "u=0, i")


def test_tls_json_profile_matches_android_148_shape():
    profile = resolve_profile("tls_json")
    headers = browser_headers(profile)
    assert profile.name == "android_chrome148_k"
    assert profile.user_agent.endswith("Chrome/148.0.0.0 Mobile Safari/537.36")
    assert ("sec-ch-ua-mobile", "?1") in headers
    assert ("Sec-Fetch-Site", "cross-site") in headers
    assert all(key != "Sec-Fetch-User" for key, _ in headers)


def test_merge_headers_replaces_in_place():
    merged = merge_headers([("User-Agent", "a"), ("Accept", "b")], {"user-agent": "c"}, [("X-Test", "1")])
    assert merged == [("user-agent", "c"), ("Accept", "b"), ("X-Test", "1")]
