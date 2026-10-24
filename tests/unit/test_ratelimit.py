import pytest

from cti.http.ratelimit import RateLimiter


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def test_allows_burst_up_to_limit_then_waits():
    clock = FakeClock()
    limiter = RateLimiter(3, 10, clock=clock, sleep=clock.sleep)
    for _ in range(3):
        limiter.acquire()
    assert clock.sleeps == []
    limiter.acquire()
    assert clock.sleeps == [pytest.approx(10.0)]


def test_window_slides():
    clock = FakeClock()
    limiter = RateLimiter(2, 10, clock=clock, sleep=clock.sleep)
    limiter.acquire()
    clock.now = 6
    limiter.acquire()
    clock.now = 10.5
    limiter.acquire()  # first call has left the window
    assert clock.sleeps == []
    limiter.acquire()  # second call (t=6) still inside the window
    assert clock.sleeps == [pytest.approx(5.5)]


@pytest.mark.parametrize("args", [(0, 1), (1, 0)])
def test_rejects_bad_config(args):
    with pytest.raises(ValueError):
        RateLimiter(*args)
