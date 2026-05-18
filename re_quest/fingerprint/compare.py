from __future__ import annotations

from typing import Any


def summarize_observation(payload: dict[str, Any]) -> dict[str, Any]:
    tls = payload.get("tls") or {}
    http2 = payload.get("http2") or {}
    http_version = payload.get("http_version") or payload.get("httpVersion")
    user_agent = payload.get("user_agent") or payload.get("user-agent")
    return {
        "ip": payload.get("ip"),
        "http_version": http_version,
        "user_agent": user_agent,
        "ja3": tls.get("ja3") or tls.get("ja3_hash"),
        "ja4": tls.get("ja4") or tls.get("ja4_r") or tls.get("ja4_hash"),
        "akamai": http2.get("akamai_fingerprint") or http2.get("akamai"),
        "tls_extensions": _extension_names(tls),
        "h2_settings": http2.get("sent_frames") or http2.get("settings"),
    }


def diff_summary(expected: dict[str, Any], observed: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    diff: dict[str, tuple[Any, Any]] = {}
    for key in sorted(set(expected) | set(observed)):
        if expected.get(key) != observed.get(key):
            diff[key] = (expected.get(key), observed.get(key))
    return diff


def _extension_names(tls: dict[str, Any]) -> list[Any]:
    extensions = tls.get("extensions") or tls.get("tls_extensions") or []
    names = []
    for item in extensions:
        if isinstance(item, dict):
            names.append(item.get("name") or item.get("type"))
        else:
            names.append(item)
    return names
