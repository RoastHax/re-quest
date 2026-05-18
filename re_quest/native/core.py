from __future__ import annotations

import base64
import socket
from typing import Iterable
from urllib.parse import unquote, urlsplit

from .h1 import build_request_bytes as build_h1_request_bytes
from .h1 import read_response as read_h1_response
from .h2 import H2ResponseReader, build_request_bytes as build_h2_request_bytes
from .tls12 import ChromeTls12Connection
from .tls13 import ChromeTls13Connection, TlsError


class NativeHttpClient:
    def __init__(
        self,
        *,
        timeout: float | None = 30,
        extension_order: tuple[int | str, ...] | None = None,
        verify: bool | str = True,
        http2: bool = True,
        tls_version: str = "auto",
    ) -> None:
        self.timeout = timeout
        self.extension_order = extension_order
        self.verify = verify
        self.http2 = http2
        self.tls_version = tls_version

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Iterable[tuple[str, str]],
        body: bytes = b"",
        proxy: str | None = None,
    ):
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http"}:
            raise ValueError("native transport supports http and https URLs")
        host = parsed.hostname
        if not host:
            raise ValueError("URL has no hostname")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "http":
            sock, absolute_form = self._open_tcp(parsed.hostname or "", port, proxy, tunnel=False)
            try:
                sock.sendall(build_h1_request_bytes(method, url, headers, body, absolute_form=absolute_form))
                return read_h1_response(sock.recv, url, method=method)
            finally:
                _close(sock)
        last_error: Exception | None = None
        for version in self._tls_attempts():
            sock = None
            tls = None
            try:
                sock, _ = self._open_tcp(host, port, proxy, tunnel=True)
                tls = self._handshake(sock, host, version)
                if tls.selected_alpn == "h2" and self.http2:
                    return self._request_h2(tls, method, url, headers, body)
                return self._request_h1_tls(tls, method, url, headers, body)
            except Exception as exc:
                last_error = exc
                if tls is not None:
                    tls.close()
                elif sock is not None:
                    _close(sock)
                if not self._can_retry_tls12(version, exc):
                    break
        if last_error is not None:
            raise last_error
        raise RuntimeError("native TLS request failed")

    def _request_h2(self, tls: ChromeTls13Connection | ChromeTls12Connection, method: str, url: str, headers, body: bytes):
        try:
            tls.send_application_data(build_h2_request_bytes(method, url, headers, body))
            reader = H2ResponseReader()
            while not reader.stream_ended:
                inner_type, plaintext = tls.read_application_data()
                if inner_type == 22:
                    continue
                if inner_type == 21:
                    raise RuntimeError("TLS alert received")
                if inner_type != 23:
                    continue
                outbound = reader.feed(plaintext)
                for frame_bytes in outbound:
                    tls.send_application_data(frame_bytes)
            return reader.build_response(url)
        finally:
            tls.close()

    def _request_h1_tls(self, tls: ChromeTls13Connection | ChromeTls12Connection, method: str, url: str, headers, body: bytes):
        pending = bytearray()

        def read_func(size: int) -> bytes:
            while not pending:
                inner_type, plaintext = tls.read_application_data()
                if inner_type == 21:
                    raise RuntimeError("TLS alert received")
                if inner_type != 23:
                    continue
                pending.extend(plaintext)
            out = bytes(pending[:size])
            del pending[:size]
            return out

        try:
            tls.send_application_data(build_h1_request_bytes(method, url, headers, body))
            return read_h1_response(read_func, url, method=method)
        finally:
            tls.close()

    def _handshake(self, sock: socket.socket, host: str, version: str) -> ChromeTls13Connection | ChromeTls12Connection:
        alpn = ["h2", "http/1.1"] if self.http2 else ["http/1.1"]
        if version == "1.2":
            tls = ChromeTls12Connection(sock, host, self.extension_order, alpn_protocols=alpn, verify=self.verify)
        elif version == "1.3":
            tls = ChromeTls13Connection(sock, host, self.extension_order, alpn_protocols=alpn, verify=self.verify)
        else:
            raise ValueError(f"unsupported TLS version selector {version!r}")
        tls.handshake()
        return tls

    def _tls_attempts(self) -> list[str]:
        value = str(self.tls_version).lower().replace("tls", "").strip()
        if value in {"auto", "", "default"}:
            return ["1.3", "1.2"]
        if value in {"1.3", "13"}:
            return ["1.3"]
        if value in {"1.2", "12"}:
            return ["1.2"]
        raise ValueError("tls_version must be 'auto', '1.3', or '1.2'")

    def _can_retry_tls12(self, version: str, exc: Exception) -> bool:
        if version != "1.3" or self._tls_attempts()[-1] != "1.2":
            return False
        text = str(exc).lower()
        if "certificate" in text or "hostname" in text or "verification" in text:
            return False
        return isinstance(exc, (TlsError, OSError, RuntimeError))

    def _open_tcp(self, host: str, port: int, proxy: str | None, *, tunnel: bool) -> tuple[socket.socket, bool]:
        if not proxy:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            if self.timeout is not None:
                sock.settimeout(self.timeout)
            return sock, False
        proxy_info = urlsplit(proxy)
        if proxy_info.scheme not in {"http", ""}:
            raise ValueError("native transport currently supports HTTP proxies only")
        proxy_host = proxy_info.hostname
        if not proxy_host:
            raise ValueError("proxy URL has no hostname")
        proxy_port = proxy_info.port or 8080
        sock = socket.create_connection((proxy_host, proxy_port), timeout=self.timeout)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        if tunnel:
            _send_connect(sock, host, port, proxy_info.username, proxy_info.password)
            return sock, False
        return sock, True


NativeHttp2Client = NativeHttpClient


def _send_connect(sock: socket.socket, host: str, port: int, username: str | None, password: str | None) -> None:
    authority = f"{host}:{port}"
    lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}", "Proxy-Connection: Keep-Alive"]
    if username is not None:
        raw = f"{unquote(username)}:{unquote(password or '')}".encode()
        lines.append("Proxy-Authorization: Basic " + base64.b64encode(raw).decode("ascii"))
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    sock.sendall(request)
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("proxy closed the CONNECT tunnel")
        buffer += chunk
        if len(buffer) > 65536:
            raise OSError("proxy CONNECT response too large")
    first = buffer.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    parts = first.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) != 200:
        raise OSError(f"proxy CONNECT failed: {first}")


def _close(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
