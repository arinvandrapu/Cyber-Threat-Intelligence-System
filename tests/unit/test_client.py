import httpx
import pytest
import respx

from cti.http.client import get_with_retry, make_client

URL = "https://api.example.com/data"


@pytest.fixture
def client():
    with make_client("test-agent") as c:
        yield c


@respx.mock
def test_retries_5xx_then_succeeds(client):
    route = respx.get(URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"ok": True})]
    )
    sleeps = []
    response = get_with_retry(client, URL, sleep=sleeps.append)
    assert response.json() == {"ok": True}
    assert route.call_count == 2
    assert len(sleeps) == 1


@respx.mock
def test_does_not_retry_client_errors(client):
    route = respx.get(URL).mock(return_value=httpx.Response(404))
    with pytest.raises(httpx.HTTPStatusError):
        get_with_retry(client, URL, sleep=lambda _: None)
    assert route.call_count == 1


@respx.mock
def test_honors_retry_after(client):
    respx.get(URL).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200)]
    )
    sleeps = []
    get_with_retry(client, URL, base_delay=0.0, sleep=sleeps.append)
    assert sleeps == [pytest.approx(7.0)]


@respx.mock
def test_retry_after_longer_than_max_delay_raises(client):
    route = respx.get(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "3600"}))
    with pytest.raises(httpx.HTTPStatusError):
        get_with_retry(client, URL, max_delay=60, sleep=lambda _: pytest.fail("should not wait"))
    assert route.call_count == 1


def test_rejects_zero_attempts(client):
    with pytest.raises(ValueError):
        get_with_retry(client, URL, max_attempts=0)


@respx.mock
def test_gives_up_after_max_attempts(client):
    route = respx.get(URL).mock(return_value=httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        get_with_retry(client, URL, max_attempts=3, sleep=lambda _: None)
    assert route.call_count == 3


@respx.mock
def test_transport_errors_are_retried(client):
    respx.get(URL).mock(side_effect=[httpx.ConnectError("boom"), httpx.Response(200)])
    assert get_with_retry(client, URL, sleep=lambda _: None).status_code == 200


@respx.mock
def test_sends_key_in_header_and_user_agent(client):
    route = respx.get(URL).mock(return_value=httpx.Response(200))
    get_with_retry(client, URL, headers={"Auth-Key": "k"})
    request = route.calls.last.request
    assert request.headers["Auth-Key"] == "k"
    assert request.headers["User-Agent"] == "test-agent"
    assert "k" not in str(request.url)
