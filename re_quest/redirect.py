from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urljoin


@dataclass(frozen=True, slots=True)
class Action:
    kind: str
    url: str | None = None
    method: str | None = None
    reason: str | None = None

    @classmethod
    def follow(cls, url: str | None = None, method: str | None = None) -> "Action":
        return cls("follow", url=url, method=method)

    @classmethod
    def stop(cls) -> "Action":
        return cls("stop")

    @classmethod
    def error(cls, reason: str) -> "Action":
        return cls("error", reason=reason)


@dataclass(frozen=True, slots=True)
class Attempt:
    response: Any
    location: str
    next_url: str
    method: str
    redirect_count: int
    max_redirects: int
    history: tuple[Any, ...]

    @property
    def status_code(self) -> int:
        return int(getattr(self.response, "status_code", 0))

    @property
    def url(self) -> str:
        return str(getattr(self.response, "url", ""))

    def follow(self, url: str | None = None, method: str | None = None) -> Action:
        return Action.follow(url or self.next_url, method=method)

    def stop(self) -> Action:
        return Action.stop()

    def error(self, reason: str) -> Action:
        return Action.error(reason)


class Policy:
    def __init__(self, handler: Callable[[Attempt], Action | bool | str | None] | None = None, *, max_redirects: int = 30):
        self.handler = handler
        self.max_redirects = max_redirects

    @classmethod
    def follow(cls, max_redirects: int = 30) -> "Policy":
        return cls(max_redirects=max_redirects)

    @classmethod
    def limit(cls, max_redirects: int) -> "Policy":
        return cls(max_redirects=max_redirects)

    @classmethod
    def none(cls) -> "Policy":
        return cls(lambda attempt: attempt.stop(), max_redirects=0)

    @classmethod
    def never(cls) -> "Policy":
        return cls.none()

    @classmethod
    def custom(cls, handler: Callable[[Attempt], Action | bool | str | None], *, max_redirects: int = 30) -> "Policy":
        return cls(handler, max_redirects=max_redirects)

    def decide(self, attempt: Attempt) -> Action:
        if attempt.redirect_count > self.max_redirects:
            return Action.error(f"too many redirects: {attempt.redirect_count} > {self.max_redirects}")
        if self.handler is None:
            return attempt.follow()
        result = self.handler(attempt)
        if isinstance(result, Action):
            return result
        if result is True or result is None:
            return attempt.follow()
        if result is False:
            return attempt.stop()
        if isinstance(result, str):
            return attempt.follow(result)
        return Action.error(f"invalid redirect policy result: {result!r}")


def normalize_policy(value: Any, *, default: Policy | None = None, max_redirects: int = 30) -> Policy:
    if value is None:
        return default or Policy.follow(max_redirects)
    if isinstance(value, Policy):
        return value
    if isinstance(value, bool):
        return Policy.follow(max_redirects) if value else Policy.none()
    if callable(value):
        return Policy.custom(value, max_redirects=max_redirects)
    raise TypeError("redirect must be a bool, callable, Policy, or None")


def next_redirect_url(base_url: str, location: str) -> str:
    return urljoin(base_url, location)
