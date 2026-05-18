<div align="center">

# re-quest

### Native Python HTTP client with browser-shaped TLS and HTTP/2 transport profiles

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Transport](https://img.shields.io/badge/transport-native%20TLS%20%2F%20HTTP2-purple)
![Status](https://img.shields.io/badge/status-experimental-orange)

`re-quest` gives Python a request-style API with direct control over TLS and HTTP/2 transport behavior.

</div>

---

## Overview

`re-quest` is a native Python HTTP client designed for transport-aware applications.

Unlike typical Python HTTP clients, `re-quest` does not rely on the standard `ssl` request path for its native transport. It constructs ClientHello messages, negotiates TLS, and emits HTTP/2 frames through its own transport implementation.

It keeps the high-level API familiar while exposing browser-shaped transport profiles for TLS, ALPN, HTTP/2 settings, ordered headers, and coherent request metadata.

---

## Highlights

- Request-style synchronous API
- `Session` support
- Cookies and redirects
- Ordered browser-style headers
- Native TLS 1.3 path
- Native TLS 1.2 fallback path
- Native HTTP/2 request framing
- HTTP/1.1 fallback
- Browser profile registry
- Fingerprint observation helpers

---

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

---

## Quick Start

```python
from re_quest import Session

with Session(profile="chrome") as session:
    response = session.get("https://example.com/")
    print(response.status_code)
    print(response.text[:200])
```

---

## Session Usage

```python
from re_quest import Session

with Session(profile="android148", timeout=20) as session:
    r1 = session.get("https://example.com/")
    r2 = session.get("https://example.com/next")

    print(r1.status_code)
    print(r2.status_code)
```

---

## Custom Headers

```python
from re_quest import Session

with Session(profile="chrome") as session:
    response = session.get(
        "https://example.com/",
        headers={
            "X-Demo": "1",
        },
    )

    print(response.status_code)
```

---

## JSON and Form Requests

```python
from re_quest import Session

with Session(profile="chrome") as session:
    json_response = session.post(
        "https://example.com/api",
        json={"hello": "world"},
    )

    form_response = session.post(
        "https://example.com/form",
        data={"username": "alice"},
    )
```

---

## Fingerprint Probe

```python
from re_quest import Session

with Session(profile="android148") as session:
    response = session.get("https://tls.peet.ws/api/all")
    data = response.json()

    print(data.get("http_version"))
    print(data.get("tls", {}).get("ja3"))
    print(data.get("http2", {}).get("akamai_fingerprint"))
```

---

## CLI

List available profiles:

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

Summarize observations:

```bash
re-quest report artifacts/fingerprints/*.json
```

---

## Built-in Profiles

```python
from re_quest import list_profiles

print(list_profiles())
```

Common aliases:

| Alias | Description |
|---|---|
| `chrome` | Default Chromium desktop profile |
| `chrome_windows` | Chromium desktop profile |
| `android148` | Android Chrome 148-style profile |
| `firefox` | Firefox-style header profile |
| `safari` | Safari-style header profile |
| `ios` | iOS Safari-style header profile |
| `edge` | Edge-style header profile |

Some profiles include native Chromium-shaped transport settings. Other profiles currently provide coherent headers while sharing the default native transport shape.

---

## Limitations

- HTTP/3/QUIC is not implemented.
- JavaScript and browser runtime APIs are out of scope.
- Browser profiles require ongoing validation as real browsers change.
- Some non-Chromium profiles are currently header-level profiles.

---

## Development

Install development dependencies:

```bash
python3 -m pip install '.[dev]'
```

Run tests:

```bash
python3 -m pytest
```

Lightweight syntax/import check:

```bash
python3 -m compileall -q re_quest tests examples
```

---

## License

MIT. See [LICENSE](LICENSE).
