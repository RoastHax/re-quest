from __future__ import annotations

import argparse
import json
import pathlib
import time
from typing import Any

from ..client import Session
from ..profiles import list_profiles
from .compare import summarize_observation

DEFAULT_ENDPOINT = "https://tls.peet.ws/api/all"


def collect_fingerprint(
    *,
    url: str = DEFAULT_ENDPOINT,
    profile: str = "chrome",
    backend: str = "auto",
    output_dir: str | pathlib.Path | None = None,
    timeout: float = 30,
    header_mode: str = "coherent",
    tls_version: str = "auto",
    http2: bool = True,
) -> dict[str, Any]:
    with Session(
        profile=profile,
        backend=backend,
        timeout=timeout,
        header_mode=header_mode,
        tls_version=tls_version,
        http2=http2,
    ) as session:
        response = session.get(url)
        resolved_profile = session.profile
    response.raise_for_status()
    try:
        observation = response.json()
    except Exception:
        observation = {"text": response.text}
    payload = {
        "metadata": {
            "timestamp": int(time.time()),
            "endpoint": url,
            "profile": profile,
            "resolved_profile": resolved_profile.name,
            "family": resolved_profile.family,
            "platform": resolved_profile.platform,
            "backend": response.backend,
            "status_code": response.status_code,
        },
        "summary": summarize_observation(observation) if isinstance(observation, dict) else {},
        "observation": observation,
    }
    if output_dir:
        output_path = pathlib.Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        file_path = output_path / f"{int(time.time())}_{profile}_{response.backend}.json"
        file_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        payload["metadata"]["file"] = str(file_path)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect external TLS/HTTP fingerprint observation")
    parser.add_argument("--url", default=DEFAULT_ENDPOINT)
    parser.add_argument("--profile", default="chrome", choices=list_profiles() + ["chrome", "firefox", "safari", "edge", "default"])
    parser.add_argument("--backend", default="auto", choices=["auto", "native"])
    parser.add_argument("--out", default="artifacts/fingerprints")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--header-mode", default="coherent", choices=["coherent", "backend", "none"])
    parser.add_argument("--tls-version", default="auto", choices=["auto", "1.3", "1.2"])
    parser.add_argument("--http1", action="store_true")
    args = parser.parse_args(argv)
    payload = collect_fingerprint(
        url=args.url,
        profile=args.profile,
        backend=args.backend,
        output_dir=args.out,
        timeout=args.timeout,
        header_mode=args.header_mode,
        tls_version=args.tls_version,
        http2=not args.http1,
    )
    print(json.dumps(payload["summary"], indent=2, ensure_ascii=False))
    if "file" in payload["metadata"]:
        print(payload["metadata"]["file"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
