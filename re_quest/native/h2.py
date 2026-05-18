from __future__ import annotations

import gzip
import zlib
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

import brotli
import zstandard
from hpack import Decoder, Encoder

from ..models import CaseInsensitiveHeaders, Response


class H2Error(Exception):
    pass


@dataclass(slots=True)
class Frame:
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes


def build_request_bytes(method: str, url: str, headers: Iterable[tuple[str, str]], body: bytes = b"") -> bytes:
    parsed = urlsplit(url)
    authority = parsed.hostname or ""
    if parsed.port and parsed.port != 443:
        authority = f"{authority}:{parsed.port}"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    hpack_headers = [
        (":method", method.upper()),
        (":authority", authority),
        (":scheme", "https"),
        (":path", path),
    ]
    hpack_headers.extend((key.lower(), value) for key, value in headers if key.lower() != "host")
    encoder = Encoder()
    header_block = encoder.encode(hpack_headers, huffman=True)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = _settings_frame(
        [
            (0x1, 65536),
            (0x2, 0),
            (0x4, 6291456),
            (0x6, 262144),
        ]
    )
    window_update = _frame(0x8, 0x0, 0, (15663105).to_bytes(4, "big"))
    priority = (0x80000000).to_bytes(4, "big") + bytes([255])
    flags = 0x04 | 0x20
    if not body:
        flags |= 0x01
    frames = [preface, settings, window_update, _frame(0x1, flags, 1, priority + header_block)]
    if body:
        frames.append(_frame(0x0, 0x01, 1, body))
    return b"".join(frames)


class H2ResponseReader:
    def __init__(self) -> None:
        self.decoder = Decoder()
        self.buffer = b""
        self.headers: list[tuple[str, str]] = []
        self.data = bytearray()
        self.status_code = 0
        self.stream_ended = False
        self._continuation_blocks: dict[int, bytearray] = {}

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer += data
        outbound: list[bytes] = []
        while len(self.buffer) >= 9:
            length = int.from_bytes(self.buffer[:3], "big")
            if len(self.buffer) < 9 + length:
                break
            header = self.buffer[:9]
            payload = self.buffer[9 : 9 + length]
            self.buffer = self.buffer[9 + length :]
            frame = Frame(header[3], header[4], int.from_bytes(header[5:9], "big") & 0x7FFFFFFF, payload)
            ack = self._handle_frame(frame)
            if ack:
                outbound.append(ack)
        return outbound

    def build_response(self, url: str) -> Response:
        headers = CaseInsensitiveHeaders((k, v) for k, v in self.headers if not k.startswith(":"))
        body = bytes(self.data)
        encoding = headers.get("content-encoding")
        if encoding:
            body = _decompress(body, encoding)
        return Response(
            url=url,
            status_code=self.status_code,
            headers=headers,
            content=body,
            backend="native",
            http_version="h2",
        )

    def _handle_frame(self, frame: Frame) -> bytes | None:
        if frame.frame_type == 0x4:
            if not (frame.flags & 0x1):
                return _frame(0x4, 0x1, 0, b"")
            return None
        if frame.frame_type == 0x1:
            self._handle_headers(frame)
        elif frame.frame_type == 0x9:
            self._handle_continuation(frame)
        elif frame.frame_type == 0x0 and frame.stream_id == 1:
            self.data.extend(frame.payload)
            if frame.flags & 0x1:
                self.stream_ended = True
        elif frame.frame_type == 0x3 and frame.stream_id == 1:
            raise H2Error("server reset stream")
        elif frame.frame_type == 0x7:
            raise H2Error("server sent GOAWAY")
        return None

    def _handle_headers(self, frame: Frame) -> None:
        payload = frame.payload
        if frame.flags & 0x8:
            pad_len = payload[0]
            payload = payload[1 : len(payload) - pad_len]
        if frame.flags & 0x20:
            payload = payload[5:]
        if frame.flags & 0x4:
            self._decode_headers(payload)
        else:
            self._continuation_blocks[frame.stream_id] = bytearray(payload)
        if frame.flags & 0x1:
            self.stream_ended = True

    def _handle_continuation(self, frame: Frame) -> None:
        block = self._continuation_blocks.setdefault(frame.stream_id, bytearray())
        block.extend(frame.payload)
        if frame.flags & 0x4:
            payload = bytes(block)
            del self._continuation_blocks[frame.stream_id]
            self._decode_headers(payload)

    def _decode_headers(self, payload: bytes) -> None:
        decoded = [(str(k), str(v)) for k, v in self.decoder.decode(payload)]
        self.headers.extend(decoded)
        for key, value in decoded:
            if key == ":status":
                self.status_code = int(value)


def _settings_frame(items: list[tuple[int, int]]) -> bytes:
    payload = b"".join(setting.to_bytes(2, "big") + value.to_bytes(4, "big") for setting, value in items)
    return _frame(0x4, 0x0, 0, payload)


def _frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def _decompress(body: bytes, encoding: str) -> bytes:
    enc = encoding.lower()
    if "br" in enc:
        return brotli.decompress(body)
    if "zstd" in enc:
        return zstandard.ZstdDecompressor().decompress(body)
    if "gzip" in enc:
        return gzip.decompress(body)
    if "deflate" in enc:
        return zlib.decompress(body)
    return body
