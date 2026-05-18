from __future__ import annotations

import json as jsonlib
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any


HeaderPairs = list[tuple[str, str]]


class CaseInsensitiveHeaders:
    def __init__(self, headers: Mapping[str, str] | Iterable[tuple[str, str]] | None = None):
        self._pairs: HeaderPairs = []
        if headers:
            if isinstance(headers, Mapping):
                iterable = headers.items()
            else:
                iterable = headers
            for key, value in iterable:
                self._pairs.append((str(key), str(value)))

    def __iter__(self) -> Iterator[str]:
        seen: set[str] = set()
        for key, _ in self._pairs:
            lower = key.lower()
            if lower not in seen:
                seen.add(lower)
                yield key

    def __len__(self) -> int:
        return len(list(iter(self)))

    def __contains__(self, key: str) -> bool:
        lower = key.lower()
        return any(k.lower() == lower for k, _ in self._pairs)

    def __getitem__(self, key: str) -> str:
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def get(self, key: str, default: str | None = None) -> str | None:
        lower = key.lower()
        for stored_key, value in reversed(self._pairs):
            if stored_key.lower() == lower:
                return value
        return default

    def items(self) -> Iterator[tuple[str, str]]:
        seen: set[str] = set()
        for key, value in reversed(self._pairs):
            lower = key.lower()
            if lower in seen:
                continue
            seen.add(lower)
            yield key, value

    def multi_items(self) -> Iterator[tuple[str, str]]:
        yield from self._pairs

    def to_dict(self) -> dict[str, str]:
        return {key: value for key, value in self.items()}

    def __repr__(self) -> str:
        return repr(self.to_dict())


@dataclass(slots=True)
class Response:
    url: str
    status_code: int
    headers: CaseInsensitiveHeaders = field(default_factory=CaseInsensitiveHeaders)
    content: bytes = b""
    reason: str = ""
    history: list["Response"] = field(default_factory=list)
    backend: str = ""
    http_version: str | None = None
    raw: Any = None
    elapsed: float | None = None
    cookies: Any = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def text(self) -> str:
        encoding = self.encoding or "utf-8"
        return self.content.decode(encoding, errors="replace")

    @property
    def encoding(self) -> str | None:
        content_type = self.headers.get("content-type") or ""
        match = re.search(r"charset=([^;]+)", content_type, re.I)
        if match:
            return match.group(1).strip("\"' ")
        return None

    def json(self, **kwargs: Any) -> Any:
        return jsonlib.loads(self.text, **kwargs)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code} for {self.url}")

    def iter_content(self, chunk_size: int = 65536) -> Iterator[bytes]:
        if self.raw is not None and hasattr(self.raw, "iter_content"):
            yield from self.raw.iter_content(chunk_size=chunk_size)
            return
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}] backend={self.backend!r}>"
