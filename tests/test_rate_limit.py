from monitor.api.rate_limit import SlidingWindowLimiter


def test_sliding_window_limit_and_expiry():
    limiter = SlidingWindowLimiter(2, 10)
    assert limiter.allow("client", now=0)
    assert limiter.allow("client", now=1)
    assert not limiter.allow("client", now=2)
    assert limiter.allow("client", now=11)


def test_zero_limit_disables_limiter():
    limiter = SlidingWindowLimiter(0)
    assert all(limiter.allow("client", now=0) for _ in range(100))
