from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

from .compare import summarize_observation


def load_artifact(path: str | pathlib.Path) -> dict[str, Any]:
    file_path = pathlib.Path(path)
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    metadata = payload.get("metadata") or {}
    if "observation" in payload:
        observation = payload.get("observation") or {}
        summary = payload.get("summary") or {}
    else:
        observation = payload
        summary = summarize_observation(observation)
        metadata = {
            "profile": "raw",
            "resolved_profile": "raw",
            "backend": "raw",
            **metadata,
        }
    return {
        "file": str(file_path),
        "profile": metadata.get("resolved_profile") or metadata.get("profile"),
        "backend": metadata.get("backend"),
        "http_version": summary.get("http_version"),
        "ja3": summary.get("ja3"),
        "ja4": summary.get("ja4"),
        "akamai": summary.get("akamai"),
        "user_agent": summary.get("user_agent"),
        "header_count": _header_count(observation),
    }


def build_report(paths: list[str | pathlib.Path]) -> dict[str, Any]:
    rows = [load_artifact(path) for path in paths]
    return {
        "count": len(rows),
        "rows": rows,
        "by_backend": {row["backend"]: row for row in rows},
    }


def _header_count(observation: dict[str, Any]) -> int | None:
    frames = ((observation.get("http2") or {}).get("sent_frames") or [])
    for frame in reversed(frames):
        headers = frame.get("headers")
        if headers:
            return len(headers)
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize saved fingerprint observations")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    report = build_report(args.files)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.out:
        pathlib.Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
