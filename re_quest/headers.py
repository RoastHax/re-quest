from __future__ import annotations

from collections.abc import Iterable, Mapping

from .models import HeaderPairs
from .profiles import BrowserProfile

HeaderInput = Mapping[str, str] | Iterable[tuple[str, str]] | None


def normalize_header_input(headers: HeaderInput) -> HeaderPairs:
    if not headers:
        return []
    if isinstance(headers, Mapping):
        return [(str(key), str(value)) for key, value in headers.items()]
    return [(str(key), str(value)) for key, value in headers]


def merge_headers(*sources: HeaderInput) -> HeaderPairs:
    merged: HeaderPairs = []
    index: dict[str, int] = {}
    for source in sources:
        for key, value in normalize_header_input(source):
            lower = key.lower()
            if value is None:
                continue
            if lower in index:
                merged[index[lower]] = (key, value)
            else:
                index[lower] = len(merged)
                merged.append((key, value))
    return merged


def browser_headers(
    profile: BrowserProfile,
    *,
    method: str = "GET",
    referer: str | None = None,
    origin: str | None = None,
    accept_language: str | None = None,
    navigation: bool | None = None,
    fetch_site: str | None = None,
    fetch_mode: str | None = None,
    fetch_dest: str | None = None,
    accept: str | None = None,
    priority: str | None = None,
    has_body: bool = False,
) -> HeaderPairs:
    method = method.upper()
    is_navigation = navigation if navigation is not None else method == "GET" and not has_body
    fetch_site = fetch_site or profile.fetch_site or ("same-origin" if origin or referer else "none")
    lang = accept_language or profile.accept_language
    selected_accept = accept or profile.accept
    if profile.family == "chromium":
        pairs: HeaderPairs = []
        if profile.sec_ch_ua:
            pairs.extend(
                [
                    ("sec-ch-ua", profile.sec_ch_ua),
                    ("sec-ch-ua-mobile", profile.sec_ch_ua_mobile or "?0"),
                    ("sec-ch-ua-platform", profile.sec_ch_ua_platform or '"Windows"'),
                ]
            )
        if is_navigation:
            pairs.append(("Upgrade-Insecure-Requests", "1"))
        pairs.extend(
            [
                ("User-Agent", profile.user_agent),
                ("Accept", selected_accept),
            ]
        )
        if origin:
            pairs.append(("Origin", origin))
        pairs.extend(
            [
                ("Sec-Fetch-Site", fetch_site),
                ("Sec-Fetch-Mode", fetch_mode or ("navigate" if is_navigation else "cors")),
            ]
        )
        if is_navigation and profile.include_sec_fetch_user:
            pairs.append(("Sec-Fetch-User", "?1"))
        pairs.append(("Sec-Fetch-Dest", fetch_dest or ("document" if is_navigation else "empty")))
        if referer:
            pairs.append(("Referer", referer))
        pairs.extend(
            [
                ("Accept-Encoding", profile.accept_encoding),
                ("Accept-Language", lang),
            ]
        )
        if priority is None:
            priority = "u=0, i" if is_navigation else "u=1, i"
        if priority:
            pairs.append(("Priority", priority))
        return pairs
    if profile.family == "firefox":
        pairs = [
            ("User-Agent", profile.user_agent),
            ("Accept", selected_accept),
            ("Accept-Language", lang),
            ("Accept-Encoding", profile.accept_encoding),
        ]
        if origin:
            pairs.append(("Origin", origin))
        if referer:
            pairs.append(("Referer", referer))
        pairs.extend(
            [
                ("Upgrade-Insecure-Requests", "1" if is_navigation else "0"),
                ("Sec-Fetch-Dest", fetch_dest or ("document" if is_navigation else "empty")),
                ("Sec-Fetch-Mode", fetch_mode or ("navigate" if is_navigation else "cors")),
                ("Sec-Fetch-Site", fetch_site),
            ]
        )
        if is_navigation:
            pairs.append(("Sec-Fetch-User", "?1"))
        return [(k, v) for k, v in pairs if not (k == "Upgrade-Insecure-Requests" and v == "0")]
    pairs = [
        ("User-Agent", profile.user_agent),
        ("Accept", selected_accept),
    ]
    if origin:
        pairs.append(("Origin", origin))
    pairs.extend(
        [
            ("Sec-Fetch-Site", fetch_site),
            ("Sec-Fetch-Mode", fetch_mode or ("navigate" if is_navigation else "cors")),
            ("Sec-Fetch-Dest", fetch_dest or ("document" if is_navigation else "empty")),
        ]
    )
    if referer:
        pairs.append(("Referer", referer))
    pairs.extend(
        [
            ("Accept-Language", lang),
            ("Accept-Encoding", profile.accept_encoding),
        ]
    )
    return pairs
