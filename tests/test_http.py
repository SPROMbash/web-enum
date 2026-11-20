"""HTTP engine: origin boundary, redirects, retries, body cap, response helpers."""

from __future__ import annotations

import gzip
from datetime import datetime, timezone

import httpx
import pytest
import respx

from tests.conftest import BASE, MakeHttp
from tests.fakes import FakeClock
from web_enum.config import load_config
from web_enum.errors import (
    BudgetExhaustedError,
    ConfigError,
    OutOfScopeRequestError,
    RequestFailedError,
)
from web_enum.http import (
    HttpClient,
    HttpResponse,
    make_async_client,
    make_limiter,
    parse_header,
    parse_retry_after,
)
from web_enum.target import parse_target


# --------------------------------------------------------------------------- #
# Basic fetch and response helpers
# --------------------------------------------------------------------------- #
async def test_fetch_returns_immutable_response(
    router: respx.MockRouter, make_http: MakeHttp
) -> None:
    router.get(BASE + "/").mock(return_value=httpx.Response(
        200,
        headers=[("Content-Type", "text/html; charset=ISO-8859-1"), ("Server", "nginx"),
                 ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")],
        content="<p>Señal</p>".encode("latin-1"),
    ))
    response = await make_http().fetch(BASE + "/")
    assert response.status == 200
    assert response.header("SERVER") == "nginx"
    assert response.header_all("set-cookie") == ["a=1", "b=2"]
    assert response.header("x-missing") is None
    assert response.is_html and response.content_type == "text/html"
    assert response.text == "<p>Señal</p>"
    assert not response.truncated and response.redirects == ()


def test_response_helpers() -> None:
    def resp(*headers: tuple[str, str], status: int = 200) -> HttpResponse:
        return HttpResponse("http://example.com/a/b", status, headers, b"caf\xc3\xa9")

    assert resp(("content-type", "text/plain; charset=nope")).text == "café"  # unknown charset
    assert resp(("content-type", "text/plain; format=flowed")).text == "café"  # no charset
    latin = HttpResponse("http://x/", 200, (("content-type", 'text/html; Charset="latin-1"'),),
                         b"caf\xe9")
    assert latin.text == "café"
    assert resp().text == "café" and resp().content_type == "" and not resp().is_html
    assert resp(("content-type", "application/xhtml+xml")).is_html
    moved = resp(("location", "../c#frag"), status=302)
    assert moved.is_redirect and moved.location == "http://example.com/c"
    assert resp(("location", "  "), status=302).location is None
    assert resp(status=302).location is None


# --------------------------------------------------------------------------- #
# Origin boundary and redirects
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    ["http://evil.test/", "https://example.com/", "http://example.com:8080/",
     "http://sub.example.com/"],
)
async def test_requests_outside_origin_are_refused(
    router: respx.MockRouter, make_http: MakeHttp, url: str
) -> None:
    http = make_http()
    with pytest.raises(OutOfScopeRequestError, match="outside the target origin"):
        await http.fetch(url)
    assert http.requests_sent == 0 and not router.calls  # nothing ever left the machine


async def test_redirects_not_followed_by_default(
    router: respx.MockRouter, make_http: MakeHttp
) -> None:
    router.get(BASE + "/old").mock(return_value=httpx.Response(301, headers={"Location": "/new"}))
    response = await make_http().fetch(BASE + "/old")
    assert response.status == 301 and response.location == BASE + "/new"


async def test_same_origin_redirects_followed(
    router: respx.MockRouter, make_http: MakeHttp
) -> None:
    router.get(BASE + "/a").mock(return_value=httpx.Response(301, headers={"Location": "/b"}))
    router.get(BASE + "/b").mock(return_value=httpx.Response(302, headers={"Location": "c#x"}))
    router.get(BASE + "/c").mock(return_value=httpx.Response(200, text="final"))
    response = await make_http().fetch(BASE + "/a", follow_redirects=True)
    assert response.url == BASE + "/c" and response.text == "final"
    assert response.redirects == (BASE + "/a", BASE + "/b")


async def test_off_origin_redirect_is_reported_not_followed(router: respx.MockRouter,
                                                            make_http: MakeHttp) -> None:
    router.get(BASE + "/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://example.com/"})
    )
    response = await make_http().fetch(BASE + "/", follow_redirects=True)
    assert response.status == 301
    assert response.blocked_redirect == "https://example.com/"
    assert len(router.calls) == 1  # https://example.com/ was never requested


async def test_redirect_loop(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.get(BASE + "/a").mock(return_value=httpx.Response(302, headers={"Location": "/b"}))
    router.get(BASE + "/b").mock(return_value=httpx.Response(302, headers={"Location": "/a"}))
    with pytest.raises(RequestFailedError, match="redirect loop"):
        await make_http().fetch(BASE + "/a", follow_redirects=True)


async def test_too_many_redirects(router: respx.MockRouter, make_http: MakeHttp) -> None:
    for i in range(10):
        router.get(f"{BASE}/r{i}").mock(
            return_value=httpx.Response(302, headers={"Location": f"/r{i + 1}"})
        )
    with pytest.raises(RequestFailedError, match="Too many redirects"):
        await make_http().fetch(BASE + "/r0", follow_redirects=True)


# --------------------------------------------------------------------------- #
# Retries and back-pressure
# --------------------------------------------------------------------------- #
async def test_retry_on_503_with_backoff(router: respx.MockRouter, make_http: MakeHttp,
                                         clock: FakeClock) -> None:
    router.get(BASE + "/").mock(side_effect=[httpx.Response(503), httpx.Response(503),
                                             httpx.Response(200, text="ok")])
    http = make_http(max_retries=2)
    response = await http.fetch(BASE + "/")
    assert response.status == 200 and http.requests_sent == 3
    assert clock.sleeps == [1.0, 2.0]  # exponential backoff via the shared limiter


async def test_retries_exhausted_returns_last_response(router: respx.MockRouter,
                                                       make_http: MakeHttp) -> None:
    router.get(BASE + "/").mock(return_value=httpx.Response(502))
    http = make_http(max_retries=1)
    assert (await http.fetch(BASE + "/")).status == 502
    assert http.requests_sent == 2


async def test_429_honours_retry_after_and_slows_everyone(
    router: respx.MockRouter, make_http: MakeHttp, clock: FakeClock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    router.get(BASE + "/").mock(side_effect=[
        httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200)
    ])
    http = make_http()
    rate_before = http.limiter.rate
    assert (await http.fetch(BASE + "/")).status == 200
    assert clock.sleeps == [7.0]
    assert http.limiter.rate == rate_before / 2
    assert "429 Too Many Requests" in caplog.text


async def test_retry_after_is_capped(router: respx.MockRouter, make_http: MakeHttp,
                                     clock: FakeClock) -> None:
    router.get(BASE + "/").mock(side_effect=[
        httpx.Response(503, headers={"Retry-After": "86400"}), httpx.Response(200)
    ])
    await make_http(max_retry_wait=30).fetch(BASE + "/")
    assert clock.sleeps == [30.0]


async def test_network_errors_retried_then_fail(
    router: respx.MockRouter, make_http: MakeHttp
) -> None:
    router.get(BASE + "/").mock(side_effect=httpx.ConnectError("connection refused"))
    http = make_http(max_retries=2)
    with pytest.raises(RequestFailedError, match="ConnectError: connection refused"):
        await http.fetch(BASE + "/")
    assert http.requests_sent == 3


async def test_timeout_then_success(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.get(BASE + "/").mock(side_effect=[httpx.ReadTimeout("slow"), httpx.Response(200)])
    assert (await make_http().fetch(BASE + "/")).status == 200


async def test_budget_exhaustion_propagates(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.get(BASE + "/").mock(return_value=httpx.Response(503))
    with pytest.raises(BudgetExhaustedError):
        await make_http(max_retries=5, budget=3).fetch(BASE + "/")


# --------------------------------------------------------------------------- #
# Body cap
# --------------------------------------------------------------------------- #
async def test_large_body_truncated(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.get(BASE + "/big").mock(return_value=httpx.Response(200, content=b"x" * 5000))
    response = await make_http(max_body=1000).fetch(BASE + "/big")
    assert len(response.body) == 1000 and response.truncated


async def test_gzip_bomb_capped_after_decompression(router: respx.MockRouter,
                                                    make_http: MakeHttp) -> None:
    bomb = gzip.compress(b"\0" * 20_000_000)  # ~20 KB on the wire, 20 MB expanded
    router.get(BASE + "/bomb").mock(
        return_value=httpx.Response(200, content=bomb, headers={"Content-Encoding": "gzip"})
    )
    response = await make_http(max_body=64 * 1024).fetch(BASE + "/bomb")
    assert len(response.body) == 64 * 1024 and response.truncated


async def test_body_exactly_at_limit_is_not_truncated(router: respx.MockRouter,
                                                      make_http: MakeHttp) -> None:
    router.get(BASE + "/").mock(return_value=httpx.Response(200, content=b"x" * 1000))
    response = await make_http(max_body=1000).fetch(BASE + "/")
    assert len(response.body) == 1000 and not response.truncated


# --------------------------------------------------------------------------- #
# Helpers and construction
# --------------------------------------------------------------------------- #
NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("120", 120.0),
        (" 5 ", 5.0),
        ("Fri, 20 Nov 2026 12:00:30 GMT", 30.0),
        ("Fri, 20 Nov 2026 11:00:00 GMT", 0.0),  # date in the past: no wait
        ("soon", None),
        ("-3", None),
    ],
)
def test_parse_retry_after(value: str | None, expected: float | None) -> None:
    assert parse_retry_after(value, now=NOW) == expected


def test_parse_retry_after_naive_date_is_utc() -> None:
    assert parse_retry_after("20 Nov 2026 12:01:00", now=NOW) == 60.0


@pytest.mark.parametrize(
    ("text", "expected"),
    [("Cookie: PHPSESSID=abc", ("Cookie", "PHPSESSID=abc")),
     ("Authorization:Bearer x:y", ("Authorization", "Bearer x:y")),
     ("X-Empty:", ("X-Empty", ""))],
)
def test_parse_header(text: str, expected: tuple[str, str]) -> None:
    assert parse_header(text) == expected


@pytest.mark.parametrize("text", ["NoColon", ": value", "Bad Name: x", "X: a\r\nInjected: 1"])
def test_parse_header_rejects(text: str) -> None:
    with pytest.raises(ConfigError, match="Invalid header"):
        parse_header(text)


async def test_make_async_client_and_limiter() -> None:
    cfg = load_config(search_user_config=False)
    async with make_async_client(cfg, {"Cookie": "a=b"}) as client:
        assert client.headers["User-Agent"] == cfg.http.user_agent
        assert client.headers["Cookie"] == "a=b"
        assert client.follow_redirects is False
        http = HttpClient.from_config(client, make_limiter(cfg), parse_target(BASE), cfg)
    assert http.max_body == cfg.http.max_body_kb * 1024
    assert http.max_retries == cfg.http.max_retries
    assert http.limiter.rate == cfg.limits.rate
    assert http.limiter.max_requests == cfg.limits.max_requests
