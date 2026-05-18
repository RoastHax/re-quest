from __future__ import annotations

from dataclasses import dataclass

from .exceptions import ProfileError


@dataclass(frozen=True, slots=True)
class BrowserProfile:
    name: str
    family: str
    platform: str
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    sec_ch_ua: str | None
    sec_ch_ua_mobile: str | None
    sec_ch_ua_platform: str | None
    tls_extension_order: tuple[int | str, ...] = (
        "grease_first",
        13,
        16,
        65281,
        18,
        35,
        5,
        43,
        65037,
        11,
        17613,
        0,
        10,
        23,
        27,
        45,
        51,
        "grease_last",
    )
    fetch_site: str = "none"
    include_sec_fetch_user: bool = True
    preferred_backend: str = "native"
    http2: bool = True
    notes: str = ""


_PROFILES: dict[str, BrowserProfile] = {
    "chrome_stable_windows": BrowserProfile(
        name="chrome_stable_windows",
        family="chromium",
        platform="windows",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua='"Chromium";v="146", "Google Chrome";v="146", "Not_A Brand";v="99"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
        preferred_backend="native",
        notes="Default coherent Chromium desktop profile.",
    ),
    "chrome_android": BrowserProfile(
        name="chrome_android",
        family="chromium",
        platform="android",
        user_agent="Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua='"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="99"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_platform='"Android"',
        preferred_backend="native",
    ),
    "android_chrome148_k": BrowserProfile(
        name="android_chrome148_k",
        family="chromium",
        platform="android",
        user_agent="Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language="en-US,en;q=0.9,ja-JP;q=0.8,ja;q=0.7,bn-BD;q=0.6,bn;q=0.5",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua='"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_platform='"Android"',
        tls_extension_order=(
            "grease_first",
            35,
            10,
            43,
            11,
            13,
            23,
            18,
            16,
            51,
            17613,
            45,
            65037,
            5,
            0,
            65281,
            27,
            "grease_last",
        ),
        fetch_site="cross-site",
        include_sec_fetch_user=False,
        preferred_backend="native",
        notes="Pinned Android Chrome 148 mobile profile.",
    ),
    "firefox_windows": BrowserProfile(
        name="firefox_windows",
        family="firefox",
        platform="windows",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua=None,
        sec_ch_ua_mobile=None,
        sec_ch_ua_platform=None,
        preferred_backend="native",
        notes="Header profile only; native TLS/H2 core currently targets Chromium.",
    ),
    "safari_macos": BrowserProfile(
        name="safari_macos",
        family="safari",
        platform="macos",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua=None,
        sec_ch_ua_mobile=None,
        sec_ch_ua_platform=None,
        preferred_backend="native",
        notes="Header profile only; native TLS/H2 core currently targets Chromium.",
    ),
    "safari_ios": BrowserProfile(
        name="safari_ios",
        family="safari",
        platform="ios",
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua=None,
        sec_ch_ua_mobile=None,
        sec_ch_ua_platform=None,
        preferred_backend="native",
        notes="Header profile only; native TLS/H2 core currently targets Chromium.",
    ),
    "edge_windows": BrowserProfile(
        name="edge_windows",
        family="chromium",
        platform="windows",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br, zstd",
        sec_ch_ua='"Chromium";v="146", "Microsoft Edge";v="146", "Not_A Brand";v="99"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
        preferred_backend="native",
        notes="Header profile only; native TLS/H2 core currently targets Chromium/Chrome transport shape.",
    ),
}

_ALIASES = {
    "chrome": "chrome_stable_windows",
    "android148": "android_chrome148_k",
    "android_chrome148": "android_chrome148_k",
    "chrome148_android": "android_chrome148_k",
    "tls_json": "android_chrome148_k",
    "chromium": "chrome_stable_windows",
    "chrome_windows": "chrome_stable_windows",
    "default": "chrome_stable_windows",
    "firefox": "firefox_windows",
    "safari": "safari_macos",
    "ios": "safari_ios",
    "edge": "edge_windows",
}


def list_profiles() -> list[str]:
    return sorted(_PROFILES)


def resolve_profile(name: str | BrowserProfile | None = None) -> BrowserProfile:
    if isinstance(name, BrowserProfile):
        return name
    normalized = (name or "default").strip().lower().replace("-", "_")
    normalized = _ALIASES.get(normalized, normalized)
    try:
        return _PROFILES[normalized]
    except KeyError as exc:
        available = ", ".join(list_profiles() + sorted(_ALIASES))
        raise ProfileError(f"unknown profile {name!r}; available: {available}") from exc
