from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from typing import Any

from .client import Session
from .fingerprint.collect import collect_fingerprint
from .fingerprint.match import build_match_report
from .fingerprint.report import build_report
from .profiles import list_profiles, resolve_profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="re-quest")
    sub = parser.add_subparsers(dest="cmd", required=True)

    profiles_cmd = sub.add_parser("profiles", help="list built-in coherent browser profiles")
    profiles_cmd.add_argument("--json", action="store_true")

    request_cmd = sub.add_parser("request", help="send a single request")
    request_cmd.add_argument("url")
    request_cmd.add_argument("-X", "--method", default="GET")
    request_cmd.add_argument("--profile", default="chrome")
    request_cmd.add_argument("--backend", default="auto", choices=["auto", "native"])
    request_cmd.add_argument("-H", "--header", action="append", default=[])
    request_cmd.add_argument("--data")
    request_cmd.add_argument("--body")
    request_cmd.add_argument("--files", action="append", default=[])
    request_cmd.add_argument("--proxy")
    request_cmd.add_argument("--tls-version", default="auto", choices=["auto", "1.3", "1.2"])
    request_cmd.add_argument("--http1", action="store_true")
    request_cmd.add_argument("--timeout", type=float, default=30)
    request_cmd.add_argument("--header-mode", default="coherent", choices=["coherent", "backend", "none"])

    fp_cmd = sub.add_parser("fingerprint", help="collect tls.peet.ws-style observation")
    fp_cmd.add_argument("--url", default="https://tls.peet.ws/api/all")
    fp_cmd.add_argument("--profile", default="chrome")
    fp_cmd.add_argument("--backend", default="auto", choices=["auto", "native"])
    fp_cmd.add_argument("--out", default="artifacts/fingerprints")
    fp_cmd.add_argument("--timeout", type=float, default=30)
    fp_cmd.add_argument("--header-mode", default="coherent", choices=["coherent", "backend", "none"])
    fp_cmd.add_argument("--tls-version", default="auto", choices=["auto", "1.3", "1.2"])
    fp_cmd.add_argument("--http1", action="store_true")

    report_cmd = sub.add_parser("report", help="summarize saved fingerprint JSON artifacts")
    report_cmd.add_argument("files", nargs="+")
    report_cmd.add_argument("--out")

    match_cmd = sub.add_parser("match", help="score candidate fingerprint artifacts against a baseline")
    match_cmd.add_argument("baseline")
    match_cmd.add_argument("candidates", nargs="+")
    match_cmd.add_argument("--out")

    args = parser.parse_args(argv)
    if args.cmd == "profiles":
        rows = [resolve_profile(name) for name in list_profiles()]
        if args.json:
            print(json.dumps([asdict(profile) for profile in rows], indent=2, ensure_ascii=False))
        else:
            for profile in rows:
                print(f"{profile.name}\t{profile.family}\t{profile.platform}")
        return 0
    if args.cmd == "request":
        headers = _parse_headers(args.header)
        with Session(
            profile=args.profile,
            backend=args.backend,
            timeout=args.timeout,
            header_mode=args.header_mode,
            http2=not args.http1,
            tls_version=args.tls_version,
        ) as session:
            response = session.request(
                args.method,
                args.url,
                headers=headers,
                data=args.data,
                body=args.body,
                files=_parse_files(args.files),
                proxy=args.proxy,
            )
        print(f"HTTP {response.status_code} via {response.backend}")
        print(response.text)
        return 0
    if args.cmd == "fingerprint":
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
    if args.cmd == "report":
        report = build_report(args.files)
        text = json.dumps(report, indent=2, ensure_ascii=False)
        if args.out:
            from pathlib import Path

            Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0
    if args.cmd == "match":
        report = build_match_report(args.baseline, args.candidates)
        text = json.dumps(report, indent=2, ensure_ascii=False)
        if args.out:
            from pathlib import Path

            Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0
    return 1


def _parse_headers(items: list[str]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for item in items:
        if ":" not in item:
            raise SystemExit(f"invalid header {item!r}; expected 'Name: value'")
        key, value = item.split(":", 1)
        headers.append((key.strip(), value.strip()))
    return headers


def _parse_files(items: list[str]) -> dict[str, tuple[str, bytes]] | None:
    if not items:
        return None
    from pathlib import Path

    files: dict[str, tuple[str, bytes]] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"invalid file {item!r}; expected 'field=path'")
        key, value = item.split("=", 1)
        path = Path(value)
        files[key] = (path.name, path.read_bytes())
    return files


if __name__ == "__main__":
    raise SystemExit(main())
