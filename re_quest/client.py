from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from .cookies import CookieJar
from .exceptions import BackendUnavailable, RedirectError, TooManyRedirects
from .headers import HeaderInput, browser_headers, merge_headers
from .models import HeaderPairs, Response
from .profiles import BrowserProfile, resolve_profile
from .redirect import Attempt, Policy, next_redirect_url, normalize_policy
from .transports import NativeTransport
from .transports.base import Transport


class Session:
    def __init__(
        self,
        *,
        profile: str | BrowserProfile | None = "chrome",
        backend: str = "auto",
        headers: HeaderInput = None,
        params: Any = None,
        cookies: Any = None,
        cookie_store: bool = True,
        cookie_provider: Any = None,
        timeout: float | tuple[float, float] | None = 30,
        verify: bool | str = True,
        http2: bool | None = None,
        http3: bool = False,
        header_mode: str = "coherent",
        accept_language: str | None = None,
        strict_backend: bool = False,
        max_redirects: int = 30,
        allow_redirects: bool | None = None,
        redirect: Any = None,
        proxy: str | None = None,
        proxies: dict[str, str] | None = None,
        auth: Any = None,
        **backend_options: Any,
    ) -> None:
        self.profile = resolve_profile(profile)
        self.backend_name = backend
        self.headers = headers
        self.params = params
        self.cookies = cookie_provider if isinstance(cookie_provider, CookieJar) else CookieJar(cookie_provider)
        if cookies:
            self.cookies.update(cookies)
        self.cookie_store = cookie_store
        self.timeout = timeout
        self.verify = verify
        self.http2 = self.profile.http2 if http2 is None else http2
        self.http3 = http3
        self.header_mode = header_mode
        self.accept_language = accept_language
        self.strict_backend = strict_backend
        self.max_redirects = max_redirects
        self.redirect_policy = normalize_policy(allow_redirects if allow_redirects is not None else redirect, max_redirects=max_redirects)
        self.proxy = proxy
        self.proxies = proxies
        self.auth = auth
        self.transport = self._make_transport(backend, backend_options)

    def _make_transport(self, backend: str, options: dict[str, Any]) -> Transport:
        default_headers = self.header_mode == "backend"
        common = {
            "timeout": self.timeout,
            "verify": self.verify,
            "http2": self.http2,
            "http3": self.http3,
            "default_headers": default_headers,
            **options,
        }
        backends = {
            "native": NativeTransport,
        }
        if backend != "auto":
            try:
                return backends[backend](self.profile, **common)
            except KeyError as exc:
                raise BackendUnavailable(f"unknown backend {backend!r}") from exc
        preferred_name = getattr(self.profile, "preferred_backend", "native")
        preferred = backends.get(preferred_name)
        if preferred is None:
            raise BackendUnavailable(f"profile preferred unknown backend {preferred_name!r}")
        return preferred(self.profile, **common)

    @property
    def backend(self) -> str:
        return self.transport.name

    @property
    def cookie_jar(self) -> CookieJar:
        return self.cookies

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Any = None,
        data: Any = None,
        json: Any = None,
        body: Any = None,
        files: Any = None,
        headers: HeaderInput = None,
        cookies: Any = None,
        timeout: float | tuple[float, float] | None = None,
        allow_redirects: bool | None = None,
        max_redirects: int | None = None,
        redirect: Any = None,
        proxy: str | None = None,
        proxies: dict[str, str] | None = None,
        verify: bool | str | None = None,
        stream: bool | None = None,
        auth: Any = None,
        cert: Any = None,
        referer: str | None = None,
        origin: str | None = None,
        navigation: bool | None = None,
        fetch_site: str | None = None,
        fetch_mode: str | None = None,
        fetch_dest: str | None = None,
        accept: str | None = None,
        priority: str | None = None,
        **kwargs: Any,
    ) -> Response:
        effective_max = self.max_redirects if max_redirects is None else max_redirects
        policy = self._resolve_redirect_policy(allow_redirects=allow_redirects, redirect=redirect, max_redirects=effective_max)
        current_method = method.upper()
        current_url = _merge_params(_merge_params(url, self.params), params)
        current_data = data
        current_json = json
        current_body = body
        current_files = files
        current_headers: HeaderInput = headers
        history: list[Response] = []
        while True:
            response = self._request_once(
                current_method,
                current_url,
                data=current_data,
                json=current_json,
                body=current_body,
                files=current_files,
                headers=current_headers,
                cookies=cookies,
                timeout=timeout,
                proxy=proxy,
                proxies=proxies,
                verify=verify,
                stream=stream,
                auth=auth,
                cert=cert,
                referer=referer,
                origin=origin,
                navigation=navigation,
                fetch_site=fetch_site,
                fetch_mode=fetch_mode,
                fetch_dest=fetch_dest,
                accept=accept,
                priority=priority,
                **kwargs,
            )
            response.cookies = CookieJar()
            response.cookies.extract(response.url, response.headers)
            if self.cookie_store:
                self.cookies.extract(response.url, response.headers)
            if response.status_code not in {301, 302, 303, 307, 308}:
                response.history = history
                return response
            location = response.headers.get("location")
            if not location:
                response.history = history
                return response
            next_url = next_redirect_url(current_url, location)
            attempt = Attempt(
                response=response,
                location=location,
                next_url=next_url,
                method=current_method,
                redirect_count=len(history) + 1,
                max_redirects=policy.max_redirects,
                history=tuple(history),
            )
            action = policy.decide(attempt)
            if action.kind == "stop":
                response.history = history
                return response
            if action.kind == "error":
                if "too many redirects" in (action.reason or ""):
                    raise TooManyRedirects(action.reason or "too many redirects")
                raise RedirectError(action.reason or "redirect policy rejected redirect")
            if len(history) >= policy.max_redirects:
                raise TooManyRedirects(f"too many redirects: {len(history) + 1} > {policy.max_redirects}")
            history.append(response)
            old_url = current_url
            current_url = action.url or next_url
            next_method = (action.method or _redirect_method(current_method, response.status_code)).upper()
            drop_body = next_method != current_method or next_method in {"GET", "HEAD"}
            current_method = next_method
            if drop_body:
                current_data = None
                current_json = None
                current_body = None
                current_files = None
            current_headers = _redirect_headers(current_headers, old_url, current_url, drop_body=drop_body)
            referer = response.url
            origin = None

    def _resolve_redirect_policy(self, *, allow_redirects: bool | None, redirect: Any, max_redirects: int) -> Policy:
        if allow_redirects is not None:
            return normalize_policy(allow_redirects, max_redirects=max_redirects)
        if redirect is not None:
            return normalize_policy(redirect, max_redirects=max_redirects)
        if max_redirects != self.redirect_policy.max_redirects:
            return Policy(self.redirect_policy.handler, max_redirects=max_redirects)
        return self.redirect_policy

    def _request_once(
        self,
        method: str,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        body: Any = None,
        files: Any = None,
        headers: HeaderInput = None,
        cookies: Any = None,
        timeout: float | tuple[float, float] | None = None,
        proxy: str | None = None,
        proxies: dict[str, str] | None = None,
        verify: bool | str | None = None,
        stream: bool | None = None,
        auth: Any = None,
        cert: Any = None,
        referer: str | None = None,
        origin: str | None = None,
        navigation: bool | None = None,
        fetch_site: str | None = None,
        fetch_mode: str | None = None,
        fetch_dest: str | None = None,
        accept: str | None = None,
        priority: str | None = None,
        **kwargs: Any,
    ) -> Response:
        has_body = data is not None or json is not None or body is not None or files is not None
        if self.header_mode == "coherent":
            generated_headers = browser_headers(
                self.profile,
                method=method,
                referer=referer,
                origin=origin,
                accept_language=self.accept_language,
                navigation=navigation,
                fetch_site=fetch_site,
                fetch_mode=fetch_mode,
                fetch_dest=fetch_dest,
                accept=accept,
                priority=priority,
                has_body=has_body,
            )
            final_headers = merge_headers(generated_headers, self.headers, headers)
            backend_default_headers = False
        elif self.header_mode == "backend":
            final_headers = merge_headers(self.headers, headers)
            backend_default_headers = True
        elif self.header_mode == "none":
            final_headers = merge_headers(self.headers, headers)
            backend_default_headers = False
        else:
            raise ValueError("header_mode must be one of: coherent, backend, none")
        if self.cookie_store:
            self.cookies.add_cookie_header(url, final_headers, extra=cookies)
        elif cookies is not None:
            CookieJar().add_cookie_header(url, final_headers, extra=cookies)
        return self.transport.request(
            method,
            url,
            headers=final_headers,
            params=None,
            data=data,
            json=json,
            body=body,
            files=files,
            cookies=None,
            timeout=self.timeout if timeout is None else timeout,
            allow_redirects=False,
            proxy=self.proxy if proxy is None else proxy,
            proxies=self.proxies if proxies is None else proxies,
            verify=self.verify if verify is None else verify,
            stream=stream,
            auth=self.auth if auth is None else auth,
            cert=cert,
            default_headers=backend_default_headers,
            **kwargs,
        )

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def close(self) -> None:
        self.transport.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


def request(method: str, url: str, **kwargs: Any) -> Response:
    session_kwargs = _session_kwargs(kwargs)
    request_kwargs = kwargs
    with Session(**session_kwargs) as session:
        return session.request(method, url, **request_kwargs)


def get(url: str, **kwargs: Any) -> Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> Response:
    return request("POST", url, **kwargs)


def put(url: str, **kwargs: Any) -> Response:
    return request("PUT", url, **kwargs)


def patch(url: str, **kwargs: Any) -> Response:
    return request("PATCH", url, **kwargs)


def delete(url: str, **kwargs: Any) -> Response:
    return request("DELETE", url, **kwargs)


def head(url: str, **kwargs: Any) -> Response:
    kwargs.setdefault("allow_redirects", False)
    return request("HEAD", url, **kwargs)


def options(url: str, **kwargs: Any) -> Response:
    return request("OPTIONS", url, **kwargs)


def _session_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    keys = {
        "profile",
        "backend",
        "headers",
        "params",
        "cookies",
        "cookie_store",
        "cookie_provider",
        "timeout",
        "verify",
        "http2",
        "http3",
        "header_mode",
        "accept_language",
        "strict_backend",
        "max_redirects",
        "allow_redirects",
        "redirect",
        "proxy",
        "proxies",
        "auth",
        "tls_version",
    }
    result: dict[str, Any] = {}
    for key in list(kwargs):
        if key in keys:
            result[key] = kwargs.pop(key)
    return result


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


def _redirect_method(method: str, status_code: int) -> str:
    if status_code == 303:
        return "HEAD" if method == "HEAD" else "GET"
    if status_code in {301, 302} and method == "POST":
        return "GET"
    return method


def _redirect_headers(headers: HeaderInput, old_url: str, new_url: str, *, drop_body: bool) -> HeaderPairs:
    if not headers:
        return []
    blocked = {"content-length", "content-type"} if drop_body else set()
    if not _same_origin(old_url, new_url):
        blocked.update({"authorization", "cookie"})
    return [(key, value) for key, value in merge_headers(headers) if key.lower() not in blocked]


def _same_origin(left: str, right: str) -> bool:
    a = urlsplit(left)
    b = urlsplit(right)
    a_port = a.port or (443 if a.scheme == "https" else 80)
    b_port = b.port or (443 if b.scheme == "https" else 80)
    return (a.scheme, a.hostname, a_port) == (b.scheme, b.hostname, b_port)
