from __future__ import annotations

from typing import Any, Protocol

from ..models import HeaderPairs, Response
from ..profiles import BrowserProfile


class Transport(Protocol):
    name: str
    profile: BrowserProfile

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
        ...

    def close(self) -> None:
        ...
