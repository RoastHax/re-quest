from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


@dataclass(slots=True)
class Cookie:
    name: str
    value: str
    domain: str
    path: str
    secure: bool = False
    expires: datetime | None = None
    host_only: bool = True

    def expired(self) -> bool:
        return self.expires is not None and datetime.now(timezone.utc) >= self.expires


class CookieJar:
    def __init__(self, cookies: Any = None) -> None:
        self._cookies: list[Cookie] = []
        if cookies:
            self.update(cookies)

    def update(self, cookies: Any, *, url: str | None = None) -> None:
        if isinstance(cookies, CookieJar):
            for cookie in cookies._cookies:
                self.set(cookie)
            return
        if isinstance(cookies, str):
            for item in cookies.split(";"):
                if "=" in item:
                    name, value = item.split("=", 1)
                    self.set_simple(name.strip(), value.strip(), url=url)
            return
        if isinstance(cookies, Mapping):
            for key, value in cookies.items():
                self.set_simple(str(key), str(value), url=url)
            return
        for key, value in cookies:
            self.set_simple(str(key), str(value), url=url)

    def set_simple(self, name: str, value: str, *, url: str | None = None) -> None:
        domain = ""
        path = "/"
        host_only = False
        secure = False
        if url:
            parsed = urlsplit(url)
            domain = (parsed.hostname or "").lower()
            path = _default_path(parsed.path)
            host_only = True
            secure = parsed.scheme == "https"
        self.set(Cookie(name=name, value=value, domain=domain, path=path, secure=secure, host_only=host_only))

    def set_cookie(
        self,
        name: str,
        value: str,
        *,
        domain: str = "",
        path: str = "/",
        secure: bool = False,
        expires: datetime | None = None,
        host_only: bool | None = None,
    ) -> None:
        self.set(
            Cookie(
                name=name,
                value=value,
                domain=domain.lower().lstrip("."),
                path=path or "/",
                secure=secure,
                expires=expires,
                host_only=(not domain) if host_only is None else host_only,
            )
        )

    def set(self, cookie: Cookie) -> None:
        self._cookies = [
            item
            for item in self._cookies
            if not (item.name == cookie.name and item.domain == cookie.domain and item.path == cookie.path)
        ]
        if not cookie.expired():
            self._cookies.append(cookie)

    def add_cookie_header(self, url: str, headers: list[tuple[str, str]], extra: Any = None) -> list[tuple[str, str]]:
        if _has_header(headers, "cookie"):
            return headers
        value = self.cookie_header(url, extra=extra)
        if value:
            headers.append(("Cookie", value))
        return headers

    def cookie_header(self, url: str, *, extra: Any = None) -> str:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        secure = parsed.scheme == "https"
        pairs: list[tuple[str, str]] = []
        kept: list[Cookie] = []
        for cookie in self._cookies:
            if cookie.expired():
                continue
            kept.append(cookie)
            if cookie.secure and not secure:
                continue
            if cookie.domain and not _domain_match(host, cookie.domain, cookie.host_only):
                continue
            if cookie.path and not path.startswith(cookie.path):
                continue
            pairs.append((cookie.name, cookie.value))
        self._cookies = kept
        if extra:
            temp = CookieJar()
            temp.update(extra, url=url)
            for cookie in temp._cookies:
                pairs.append((cookie.name, cookie.value))
        return "; ".join(f"{name}={value}" for name, value in pairs)

    def extract(self, url: str, headers: Any) -> None:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        default_path = _default_path(parsed.path)
        for key, value in getattr(headers, "multi_items", headers.items)():
            if key.lower() != "set-cookie":
                continue
            simple = SimpleCookie()
            try:
                simple.load(value)
            except Exception:
                continue
            for morsel in simple.values():
                domain = morsel["domain"].lstrip(".").lower() if morsel["domain"] else host
                path = morsel["path"] or default_path
                expires = _parse_expires(morsel["expires"])
                max_age = morsel["max-age"]
                if max_age:
                    try:
                        seconds = int(max_age)
                        if seconds <= 0:
                            expires = datetime.now(timezone.utc)
                    except ValueError:
                        pass
                self.set(
                    Cookie(
                        name=morsel.key,
                        value=morsel.value,
                        domain=domain,
                        path=path,
                        secure=bool(morsel["secure"]),
                        expires=expires,
                        host_only=not bool(morsel["domain"]),
                    )
                )

    def get(self, name: str, default: str | None = None) -> str | None:
        for cookie in reversed(self._cookies):
            if cookie.name == name and not cookie.expired():
                return cookie.value
        return default

    def get_dict(self) -> dict[str, str]:
        return {cookie.name: cookie.value for cookie in self._cookies if not cookie.expired()}

    def delete(self, name: str, *, domain: str | None = None, path: str | None = None) -> None:
        self._cookies = [
            cookie
            for cookie in self._cookies
            if not (
                cookie.name == name
                and (domain is None or cookie.domain == domain.lower().lstrip("."))
                and (path is None or cookie.path == path)
            )
        ]

    def clear(self) -> None:
        self._cookies.clear()

    def copy(self) -> "CookieJar":
        jar = CookieJar()
        for cookie in self._cookies:
            jar.set(cookie)
        return jar

    def __iter__(self):
        return iter(self._cookies)

    def __len__(self) -> int:
        return len([cookie for cookie in self._cookies if not cookie.expired()])


def _has_header(headers: list[tuple[str, str]], name: str) -> bool:
    lower = name.lower()
    return any(key.lower() == lower for key, _ in headers)


def _domain_match(host: str, domain: str, host_only: bool) -> bool:
    domain = domain.lower().lstrip(".")
    if host_only:
        return host == domain
    return host == domain or host.endswith("." + domain)


def _default_path(path: str) -> str:
    if not path or not path.startswith("/"):
        return "/"
    if path.count("/") == 1:
        return "/"
    return path.rsplit("/", 1)[0] or "/"


def _parse_expires(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None
