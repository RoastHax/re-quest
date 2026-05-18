# re-quest

A native Python HTTP client with browser-shaped TLS and HTTP/2 transport profiles.

`re-quest` provides a request-style API while keeping transport-fingerprint behavior explicit and configurable. It constructs ClientHello messages, negotiates TLS, and emits HTTP/2 frames from its own native transport code instead of relying on Python's standard `ssl` request path.

## Highlights

- Request-style synchronous API with `Session`, `get`, `post`, `put`, `patch`, `delete`, `head`, and `options`.
- Cookie jar, redirects, timeouts, request bodies, JSON, forms, and custom headers.
- Ordered browser-style headers and coherent browser profile metadata.
- Native TLS 1.3 path.
- Native TLS 1.2 fallback path.
- Native HTTP/2 request framing and response parsing.
- HTTP/1.1 fallback path.
- Fingerprint collection and reporting helpers for JSON observation endpoints.

## Scope

`re-quest` is a standalone Python package. It does not launch a browser, does not use browser automation, and does not wrap external HTTP/TLS clients for its native transport.

It focuses on the network transport layer: TLS, ALPN, HTTP/2 settings, request framing, and coherent request headers. Browser runtime behavior such as JavaScript APIs, DOM state, graphics fingerprints, and user interaction signals is outside the scope of this project.

## Installation

```bash
python3 -m pip install .
```

Runtime dependencies:

```text
cryptography>=42
hpack>=4
Brotli>=1
zstandard>=0.23
```

Development dependencies:

```bash
python3 -m pip install '.[dev]'
```

## Quick start

```python
from re_quest import Session

with Session(profile="chrome") as session:
    response = session.get("https://example.com/")
    print(response.status_code)
    print(response.text[:200])
```

## Sessions

```python
from re_quest import Session

with Session(profile="android148", timeout=20) as session:
    first = session.get("https://example.com/")
    second = session.get("https://example.com/next")
    print(first.status_code, second.status_code)
```

## Custom headers

```python
from re_quest import Session

with Session(profile="chrome") as session:
    response = session.get(
        "https://example.com/",
        headers={"X-Demo": "1"},
    )
    print(response.status_code)
```

## Form and JSON requests

```python
from re_quest import Session

with Session(profile="chrome") as session:
    form_response = session.post(
        "https://example.com/form",
        data={"username": "alice", "action": "submit"},
    )

    json_response = session.post(
        "https://example.com/api",
        json={"hello": "world"},
    )
```

## Fingerprint probe

```python
from re_quest import Session

with Session(profile="android148") as session:
    response = session.get("https://tls.peet.ws/api/all")
    data = response.json()
    print(data.get("http_version"))
    print(data.get("tls", {}).get("ja3"))
    print(data.get("http2", {}).get("akamai_fingerprint"))
```

## CLI

List built-in profiles:

```bash
re-quest profiles
```

Send a request:

```bash
re-quest request https://example.com/ --profile chrome
```

Collect a fingerprint observation:

```bash
re-quest fingerprint --profile android148 --out artifacts/fingerprints
```

Summarize saved observations:

```bash
re-quest report artifacts/fingerprints/*.json
```

## Built-in profiles

```python
from re_quest import list_profiles

print(list_profiles())
```

Common aliases:

- `chrome`
- `chrome_windows`
- `android148`
- `firefox`
- `safari`
- `ios`
- `edge`

Some profiles include native Chromium-shaped transport settings. Other profiles currently provide coherent headers while sharing the default native transport shape.

## Architecture

```text
re_quest/
  client.py              high-level Session and shortcut request API
  cookies.py             cookie storage and matching
  headers.py             coherent ordered browser headers
  profiles.py            profile registry
  redirect.py            redirect policy and history
  native/
    core.py              socket connection and native transport orchestration
    tls13.py             TLS 1.3 handshake and records
    tls12.py             TLS 1.2 fallback handshake path
    h2.py                HTTP/2 frame construction and response reader
    h1.py                HTTP/1.1 fallback path
  transports/
    native.py            transport adapter used by Session
  fingerprint/
    collect.py           observation collection helper
    compare.py           observation summarizer
    report.py            report builder
```

## Design notes

The high-level API is intentionally familiar, while fingerprint-sensitive behavior is represented as explicit profile data and native transport code. A profile can control values such as user agent, client hints, fetch metadata, TLS extension order, ALPN, and HTTP/2 behavior.

The native transport uses Python for protocol construction and parsing. Low-level cryptographic operations are provided by `cryptography`.

## Limitations

- HTTP/3/QUIC is not implemented.
- JavaScript and browser runtime APIs are out of scope.
- Browser profiles require ongoing validation as real browsers change.
- Some non-Chromium profiles are currently header-level profiles rather than complete native transport profiles.

## Testing

```bash
python3 -m pip install '.[dev]'
python3 -m pytest
```

A lightweight syntax/import check without installing test dependencies:

```bash
python3 -m compileall -q re_quest tests examples
```

## License

MIT. See [LICENSE](LICENSE).
