"""Small bounded HTTPS JSON transport with secret-safe failures."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

Transport = Callable[[str, float, int], tuple[str, bytes]]


class HttpError(RuntimeError):
    """Base error for provider HTTP reads."""


class HttpConfigurationError(HttpError):
    """The endpoint configuration is unsafe."""


class HttpTransportError(HttpError):
    """The HTTPS request failed without exposing its URL."""


class HttpProtocolError(HttpError):
    """The response is not bounded strict JSON."""


def _validate_url(url: str) -> None:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise HttpConfigurationError("HTTP endpoint must be an absolute HTTPS URL")


def _default_transport(url: str, timeout: float, max_response_bytes: int) -> tuple[str, bytes]:
    request = Request(  # noqa: S310 -- URL is validated before this boundary
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "agent-bridge-guard/0.1",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            geturl = getattr(response, "geturl", None)
            final_url = url if geturl is None else geturl()
            _validate_url(final_url)
            content_type = response.headers.get("Content-Type", "")
            body = cast(bytes, response.read(max_response_bytes + 1))
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise HttpTransportError("HTTPS request failed") from exc
    return content_type, body


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value}")


def get_json(
    url: str,
    *,
    timeout: float = 15.0,
    max_response_bytes: int = 1_000_000,
    transport: Transport | None = None,
) -> object:
    """Return one decoded strict-JSON value without echoing endpoint details."""

    _validate_url(url)
    if timeout <= 0 or max_response_bytes <= 0:
        raise ValueError("HTTP timeout and byte limit must be positive")
    content_type, body = (transport or _default_transport)(
        url,
        timeout,
        max_response_bytes,
    )
    if not content_type.lower().startswith("application/json"):
        raise HttpProtocolError("HTTPS response is not JSON")
    if len(body) > max_response_bytes:
        raise HttpProtocolError("HTTPS response exceeds configured byte limit")
    try:
        return json.loads(
            body.decode("utf-8"),
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HttpProtocolError("HTTPS response is not strict JSON") from exc
