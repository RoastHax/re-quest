from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

from .compare import summarize_observation


def build_match_report(baseline_path: str | pathlib.Path, candidate_paths: list[str | pathlib.Path]) -> dict[str, Any]:
    baseline = _load(baseline_path)
    candidates = [_load(path) for path in candidate_paths]
    return {
        "baseline": _identity(baseline),
        "candidates": [_match_one(baseline, candidate) for candidate in candidates],
        "notes": [
            "Exact JA3 is intentionally not scored because Chromium permutes TLS extension order and GREASE values.",
            "JA4, Akamai H2, header order, H2 SETTINGS, and H2 priority are scored.",
        ],
    }


def _load(path: str | pathlib.Path) -> dict[str, Any]:
    file_path = pathlib.Path(path)
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    observation = payload.get("observation", payload)
    metadata = payload.get("metadata") or {}
    summary = payload.get("summary") or summarize_observation(observation)
    return {"file": str(file_path), "metadata": metadata, "summary": summary, "observation": observation}


def _identity(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item["metadata"]
    summary = item["summary"]
    return {
        "file": item["file"],
        "backend": metadata.get("backend"),
        "profile": metadata.get("resolved_profile") or metadata.get("profile"),
        "http_version": summary.get("http_version"),
        "user_agent": summary.get("user_agent"),
        "ja3": summary.get("ja3"),
        "ja4": summary.get("ja4"),
        "akamai": summary.get("akamai"),
    }


def _match_one(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "http_version": _summary_field(baseline, candidate, "http_version"),
        "user_agent": _summary_field(baseline, candidate, "user_agent"),
        "ja4": _summary_field(baseline, candidate, "ja4"),
        "akamai_h2": _summary_field(baseline, candidate, "akamai"),
        "h2_settings": _compare(_h2_settings(baseline["observation"]), _h2_settings(candidate["observation"])),
        "h2_headers_exact_order": _compare(_h2_headers(baseline["observation"]), _h2_headers(candidate["observation"])),
        "h2_priority": _compare(_h2_priority(baseline["observation"]), _h2_priority(candidate["observation"])),
        "tls_ciphers_without_grease": _compare(_tls_ciphers(baseline["observation"]), _tls_ciphers(candidate["observation"])),
        "tls_extension_set_without_grease": _compare(
            sorted(_tls_extensions(baseline["observation"])),
            sorted(_tls_extensions(candidate["observation"])),
        ),
    }
    matched = sum(1 for check in checks.values() if check["match"])
    total = len(checks)
    result = _identity(candidate)
    result.update(
        {
            "match_score": matched / total,
            "matched": matched,
            "total": total,
            "checks": checks,
            "ja3_observed": {
                "baseline": baseline["summary"].get("ja3"),
                "candidate": candidate["summary"].get("ja3"),
            },
        }
    )
    return result


def _summary_field(left: dict[str, Any], right: dict[str, Any], key: str) -> dict[str, Any]:
    return _compare(left["summary"].get(key), right["summary"].get(key))


def _compare(left: Any, right: Any) -> dict[str, Any]:
    return {"match": left == right, "baseline": left, "candidate": right}


def _h2_frames(observation: dict[str, Any]) -> list[dict[str, Any]]:
    return (observation.get("http2") or {}).get("sent_frames") or []


def _h2_headers(observation: dict[str, Any]) -> list[str]:
    for frame in reversed(_h2_frames(observation)):
        if frame.get("frame_type") == "HEADERS" and frame.get("headers"):
            return frame["headers"]
    return []


def _h2_priority(observation: dict[str, Any]) -> dict[str, Any] | None:
    for frame in reversed(_h2_frames(observation)):
        if frame.get("frame_type") == "HEADERS":
            return frame.get("priority")
    return None


def _h2_settings(observation: dict[str, Any]) -> list[str]:
    for frame in _h2_frames(observation):
        if frame.get("frame_type") == "SETTINGS":
            return frame.get("settings") or []
    return []


def _tls_ciphers(observation: dict[str, Any]) -> list[str]:
    ciphers = (observation.get("tls") or {}).get("ciphers") or []
    return [item for item in ciphers if "GREASE" not in str(item)]


def _tls_extensions(observation: dict[str, Any]) -> list[str]:
    extensions = (observation.get("tls") or {}).get("extensions") or []
    result = []
    for item in extensions:
        value = item.get("name") if isinstance(item, dict) else str(item)
        if value and "GREASE" not in value:
            result.append(value)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score candidate fingerprint artifacts against a baseline")
    parser.add_argument("baseline")
    parser.add_argument("candidates", nargs="+")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    report = build_match_report(args.baseline, args.candidates)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.out:
        pathlib.Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
