from __future__ import annotations

from typing import Callable, Iterable
from urllib.parse import urlsplit

from ..models import CaseInsensitiveHeaders, Response
from .h2 import _decompress


class H1Error(Exception):
    pass


def build_request_bytes(
    method: str,
    url: str,
    headers: Iterable[tuple[str, str]],
    body: bytes = b"",
    *,
    absolute_form: bool = False,
) -> bytes:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    authority = host if not port or port == default_port else f"{host}:{port}"
    if absolute_form:
        target = url
    else:
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
    pairs = [(str(k), str(v)) for k, v in headers]
    if not _has_header(pairs, "host"):
        pairs.insert(0, ("Host", authority))
    if body and not _has_header(pairs, "content-length"):
        pairs.append(("Content-Length", str(len(body))))
    if not _has_header(pairs, "connection"):
        pairs.append(("Connection", "close"))
    head = [f"{method.upper()} {target} HTTP/1.1"]
    head.extend(f"{key}: {value}" for key, value in pairs)
    return ("\r\n".join(head) + "\r\n\r\n").encode("iso-8859-1") + body


def read_response(read_func: Callable[[int], bytes], url: str, *, method: str = "GET") -> Response:
    while True:
        header_block, rest = _read_header_block(read_func, b"")
        status_line, headers = _parse_headers(header_block)
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise H1Error(f"invalid HTTP status line: {status_line!r}")
        status_code = int(parts[1])
        reason = parts[2] if len(parts) > 2 else ""
        if 100 <= status_code < 200 and status_code not in {101}:
            continue
        break
    ci_headers = CaseInsensitiveHeaders(headers)
    body = b""
    if method.upper() != "HEAD" and status_code not in {101, 204, 304}:
        transfer_encoding = ci_headers.get("transfer-encoding", "") or ""
        content_length = ci_headers.get("content-length")
        if "chunked" in transfer_encoding.lower():
            body, rest = _read_chunked(read_func, rest)
        elif content_length is not None:
            length = int(content_length)
            body = rest + _read_exact_from_func(read_func, length - len(rest)) if len(rest) < length else rest[:length]
        else:
            chunks = [rest] if rest else []
            while True:
                data = read_func(65536)
                if not data:
                    break
                chunks.append(data)
            body = b"".join(chunks)
    encoding = ci_headers.get("content-encoding")
    if encoding and body:
        body = _decompress(body, encoding)
    return Response(
        url=url,
        status_code=status_code,
        headers=ci_headers,
        content=body,
        reason=reason,
        backend="native",
        http_version="http/1.1",
    )


def _read_header_block(read_func: Callable[[int], bytes], initial: bytes) -> tuple[bytes, bytes]:
    buffer = initial
    while b"\r\n\r\n" not in buffer:
        data = read_func(65536)
        if not data:
            raise H1Error("unexpected EOF while reading response headers")
        buffer += data
        if len(buffer) > 1024 * 1024:
            raise H1Error("response headers are too large")
    head, rest = buffer.split(b"\r\n\r\n", 1)
    return head, rest


def _parse_headers(block: bytes) -> tuple[str, list[tuple[str, str]]]:
    lines = block.decode("iso-8859-1").split("\r\n")
    status_line = lines[0]
    headers: list[tuple[str, str]] = []
    current_key: str | None = None
    current_value: list[str] = []
    for line in lines[1:]:
        if line.startswith((" ", "\t")) and current_key is not None:
            current_value.append(line.strip())
            continue
        if current_key is not None:
            headers.append((current_key, " ".join(current_value)))
        if ":" not in line:
            current_key = None
            current_value = []
            continue
        key, value = line.split(":", 1)
        current_key = key.strip()
        current_value = [value.strip()]
    if current_key is not None:
        headers.append((current_key, " ".join(current_value)))
    return status_line, headers


def _read_chunked(read_func: Callable[[int], bytes], buffer: bytes) -> tuple[bytes, bytes]:
    body = bytearray()
    while True:
        while b"\r\n" not in buffer:
            data = read_func(65536)
            if not data:
                raise H1Error("unexpected EOF in chunk size")
            buffer += data
        line, buffer = buffer.split(b"\r\n", 1)
        size_text = line.split(b";", 1)[0].strip()
        size = int(size_text, 16)
        if size == 0:
            if buffer.startswith(b"\r\n"):
                return bytes(body), buffer[2:]
            while b"\r\n\r\n" not in buffer:
                data = read_func(65536)
                if not data:
                    return bytes(body), b""
                buffer += data
            _, rest = buffer.split(b"\r\n\r\n", 1)
            return bytes(body), rest
        needed = size + 2
        if len(buffer) < needed:
            buffer += _read_exact_from_func(read_func, needed - len(buffer))
        body.extend(buffer[:size])
        buffer = buffer[needed:]


def _read_exact_from_func(read_func: Callable[[int], bytes], length: int) -> bytes:
    if length <= 0:
        return b""
    chunks = []
    remaining = length
    while remaining > 0:
        data = read_func(remaining)
        if not data:
            raise H1Error("unexpected EOF while reading response body")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _has_header(headers: list[tuple[str, str]], name: str) -> bool:
    lower = name.lower()
    return any(key.lower() == lower for key, _ in headers)
