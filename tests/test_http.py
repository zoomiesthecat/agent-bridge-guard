from __future__ import annotations

import pytest

from agent_bridge_guard.http import (
    HttpConfigurationError,
    HttpProtocolError,
    _default_transport,
    get_json,
)


def test_get_json_requires_safe_https_and_strict_bounded_json() -> None:
    with pytest.raises(HttpConfigurationError):
        get_json("http://example.test", transport=lambda *_: ("application/json", b"{}"))
    with pytest.raises(HttpConfigurationError):
        get_json(
            "https://user:secret@example.test",
            transport=lambda *_: ("application/json", b"{}"),
        )

    assert get_json(
        "https://example.test/path",
        transport=lambda *_: ("application/json; charset=utf-8", b'{"ok":true}'),
    ) == {"ok": True}


def test_get_json_rejects_type_size_and_nonfinite_values_without_url_leak() -> None:
    endpoint = "https://example.test/private-path-token"
    with pytest.raises(HttpProtocolError) as content_type:
        get_json(endpoint, transport=lambda *_: ("text/html", b"{}"))
    assert "private-path-token" not in str(content_type.value)

    with pytest.raises(HttpProtocolError, match="byte limit"):
        get_json(
            endpoint,
            max_response_bytes=2,
            transport=lambda *_: ("application/json", b"{}x"),
        )
    with pytest.raises(HttpProtocolError, match="strict JSON"):
        get_json(
            endpoint,
            transport=lambda *_: ("application/json", b'{"value":NaN}'),
        )


def test_default_transport_rejects_redirect_to_non_https_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RedirectedResponse:
        headers = {"Content-Type": "application/json"}

        def __enter__(self) -> RedirectedResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return "http://redirected.example.test/private-path"

        def read(self, _limit: int) -> bytes:
            pytest.fail("unsafe redirect body must not be read")

    monkeypatch.setattr(
        "agent_bridge_guard.http.urlopen", lambda *_args, **_kwargs: RedirectedResponse()
    )

    with pytest.raises(HttpConfigurationError, match="absolute HTTPS URL"):
        _default_transport("https://example.test/path", 1.0, 1024)
