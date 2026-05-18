from __future__ import annotations

import base64
import json as jsonlib
import os
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from ..exceptions import TransportError
from ..models import HeaderPairs, Response
from ..native import NativeHttpClient
from ..profiles import BrowserProfile


class NativeTransport:
    name = "native"

    def __init__(
        self,
        profile: BrowserProfile,
        *,
        timeout: float | tuple[float, float] | None = 30,
        verify: bool | str = True,
        http2: bool = True,
        http3: bool = False,
        tls_version: str = "auto",
        **_: Any,
    ) -> None:
        if profile.family != "chromium":
            raise TransportError("native transport currently implements Chromium-family TLS profiles")
        if http3:
            raise TransportError("native transport does not implement HTTP/3 yet")
        self.profile = profile
        self.timeout = _timeout_value(timeout)
        self.verify = verify
        self.http2 = http2
        self.tls_version = tls_version
        self.client = NativeHttpClient(
            timeout=self.timeout,
            extension_order=profile.tls_extension_order,
            verify=verify,
            http2=http2,
            tls_version=tls_version,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: HeaderPairs | None = None,
        params: Any = None,
        data: Any = None,
        json: Any = None,
        body: Any = None,
        files: Any = None,
        cookies: Any = None,
        timeout: float | tuple[float, float] | None = None,
        allow_redirects: bool | None = None,
        proxy: str | None = None,
        proxies: dict[str, str] | None = None,
        verify: bool | str | None = None,
        stream: bool | None = None,
        auth: Any = None,
        cert: Any = None,
        default_headers: bool = False,
        **kwargs: Any,
    ) -> Response:
        if cert is not None:
            raise TransportError("native transport client certificates are not implemented yet")
        final_url = _merge_params(url, params)
        final_headers = list(headers or [])
        if cookies is not None and not _has_header(final_headers, "cookie"):
            final_headers.append(("Cookie", _cookie_header(cookies)))
        if auth is not None and not _has_header(final_headers, "authorization"):
            final_headers.append(("Authorization", _basic_auth(auth)))
        body_bytes, content_type = _body_bytes(data=data, json=json, body=body, files=files)
        if body_bytes and not _has_header(final_headers, "content-length"):
            final_headers.append(("Content-Length", str(len(body_bytes))))
        if content_type and not _has_header(final_headers, "content-type"):
            final_headers.append(("Content-Type", content_type))
        selected_proxy = proxy or _select_proxy(final_url, proxies)
        previous_timeout = self.client.timeout
        previous_verify = self.client.verify
        if timeout is not None:
            self.client.timeout = _timeout_value(timeout)
        if verify is not None:
            self.client.verify = verify
        try:
            return self.client.request(method, final_url, headers=final_headers, body=body_bytes, proxy=selected_proxy)
        except Exception as exc:
            raise TransportError(f"native request failed: {exc}") from exc
        finally:
            self.client.timeout = previous_timeout
            self.client.verify = previous_verify

    def close(self) -> None:
        pass


def _timeout_value(timeout: float | tuple[float, float] | None) -> float | None:
    if timeout is None:
        return None
    if isinstance(timeout, tuple):
        return sum(float(part) for part in timeout)
    return float(timeout)


def _body_bytes(*, data: Any = None, json: Any = None, body: Any = None, files: Any = None) -> tuple[bytes, str | None]:
    if json is not None:
        return jsonlib.dumps(json, separators=(",", ":")).encode(), "application/json"
    if files is not None:
        return _multipart_body(data, files)
    if body is not None:
        return _to_bytes(body), None
    if data is None:
        return b"", None
    if isinstance(data, dict):
        return urlencode(data, doseq=True).encode(), "application/x-www-form-urlencoded"
    return _to_bytes(data), None


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode()
    if hasattr(value, "read"):
        chunk = value.read()
        return chunk if isinstance(chunk, bytes) else str(chunk).encode()
    return bytes(value)


def _multipart_body(data: Any, files: Any) -> tuple[bytes, str]:
    boundary = "----re-quest-" + os.urandom(12).hex()
    parts: list[bytes] = []
    for name, value in _iter_fields(data):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
        )
    for name, value in _iter_fields(files):
        filename = name
        content_type = "application/octet-stream"
        content: Any = value
        if isinstance(value, tuple):
            if len(value) == 2:
                filename, content = value
            elif len(value) >= 3:
                filename, content, content_type = value[:3]
        if hasattr(content, "read"):
            content = content.read()
        content_bytes = _to_bytes(content)
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n".encode()
            + content_bytes
            + b"\r\n"
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _iter_fields(value: Any):
    if value is None:
        return []
    if isinstance(value, dict):
        return [(str(k), v) for k, v in value.items()]
    return [(str(k), v) for k, v in value]


def _merge_params(url: str, params: Any) -> str:
    if not params:
        return url
    parsed = urlsplit(url)
    if isinstance(params, (str, bytes)):
        query = params.decode() if isinstance(params, bytes) else params
    else:
        query = urlencode(params, doseq=True)
    combined = parsed.query + ("&" if parsed.query and query else "") + query
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, combined, parsed.fragment))


def _select_proxy(url: str, proxies: dict[str, str] | None) -> str | None:
    if not proxies:
        return None
    scheme = urlsplit(url).scheme
    return proxies.get(scheme) or proxies.get(f"{scheme}://") or proxies.get("all") or proxies.get("all://")


def _cookie_header(cookies: Any) -> str:
    if isinstance(cookies, str):
        return cookies
    if isinstance(cookies, dict):
        return "; ".join(f"{key}={value}" for key, value in cookies.items())
    return "; ".join(f"{key}={value}" for key, value in cookies)


def _basic_auth(auth: Any) -> str:
    if isinstance(auth, str):
        raw = auth.encode()
    else:
        username, password = auth
        raw = f"{username}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _has_header(headers: HeaderPairs, name: str) -> bool:
    lower = name.lower()
    return any(key.lower() == lower for key, _ in headers)
