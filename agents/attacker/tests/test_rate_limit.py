import unittest

from aegis_attacker.rate_limit import (
    REQUEST_BURST,
    Backoff,
    RateLimiter,
    SlidingWindowLimiter,
    TokenBucket,
    parse_retry_after,
)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class TestTokenBucket(unittest.TestCase):
    def test_burst_then_empty(self):
        clk = FakeClock()
        b = TokenBucket(rate=10.0, capacity=20, clock=clk)
        for _ in range(20):
            self.assertTrue(b.try_acquire())
        self.assertFalse(b.try_acquire())

    def test_refill_over_time(self):
        clk = FakeClock()
        b = TokenBucket(rate=10.0, capacity=20, clock=clk)
        for _ in range(20):
            b.try_acquire()
        clk.advance(1.0)
        for _ in range(10):
            self.assertTrue(b.try_acquire())
        self.assertFalse(b.try_acquire())


class TestSlidingWindowSubmit(unittest.TestCase):
    def test_30_per_rolling_60s(self):
        clk = FakeClock()
        w = SlidingWindowLimiter(max_events=30, window=60.0, clock=clk)
        for _ in range(30):
            self.assertTrue(w.try_acquire())
        self.assertFalse(w.try_acquire())  # 31번째 거부

    def test_oldest_exits_window(self):
        clk = FakeClock()
        w = SlidingWindowLimiter(max_events=30, window=60.0, clock=clk)
        for _ in range(30):
            w.try_acquire()
        self.assertFalse(w.try_acquire())
        clk.advance(60.0)  # t=0 기록들이 창을 벗어남
        for _ in range(30):
            self.assertTrue(w.try_acquire())
        self.assertFalse(w.try_acquire())

    def test_no_burst_beyond_max(self):
        # 창이 오래 비어 있어도 max 초과 burst 없음
        clk = FakeClock()
        w = SlidingWindowLimiter(max_events=30, window=60.0, clock=clk)
        clk.advance(600.0)
        allowed = sum(1 for _ in range(100) if w.try_acquire())
        self.assertEqual(allowed, 30)

    def test_wait_time_until_slot(self):
        clk = FakeClock()
        w = SlidingWindowLimiter(max_events=1, window=60.0, clock=clk)
        w.try_acquire()  # t=0
        self.assertAlmostEqual(w.wait_time(), 60.0, places=6)
        clk.advance(30.0)
        self.assertAlmostEqual(w.wait_time(), 30.0, places=6)

    def test_via_ratelimiter(self):
        clk = FakeClock()
        rl = RateLimiter(clock=clk)
        for _ in range(30):
            self.assertTrue(rl.try_submit())
        self.assertFalse(rl.try_submit())


class TestRequestRate(unittest.TestCase):
    def test_shared_global_limit(self):
        clk = FakeClock()
        rl = RateLimiter(clock=clk)
        allowed = sum(1 for _ in range(100) if rl.try_request())
        self.assertEqual(allowed, REQUEST_BURST)

    def test_acquire_blocks_until_available(self):
        clk = FakeClock()
        slept = []

        def fake_sleep(dt):
            slept.append(dt)
            clk.advance(dt)

        rl = RateLimiter(clock=clk, sleep=fake_sleep)
        for _ in range(20):
            rl.try_request()
        rl.acquire_request()
        self.assertTrue(len(slept) >= 1)


class TestRetryAfter(unittest.TestCase):
    def test_delta_seconds(self):
        self.assertEqual(parse_retry_after("120"), 120.0)
        self.assertEqual(parse_retry_after("0"), 0.0)

    def test_http_date(self):
        # 기준 시각(2025) 대비 미래 날짜(2026) → 양수 초
        secs = parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT",
                                 now_epoch=1760000000.0)
        self.assertIsNotNone(secs)
        self.assertGreater(secs, 0)

    def test_past_http_date_clamped_zero(self):
        secs = parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT",
                                 now_epoch=1760000000.0)
        self.assertEqual(secs, 0.0)

    def test_invalid_returns_none(self):
        self.assertIsNone(parse_retry_after("not-a-date"))
        self.assertIsNone(parse_retry_after(""))
        self.assertIsNone(parse_retry_after(None))


class TestBackoff(unittest.TestCase):
    def test_exponential_with_cap_and_reset(self):
        b = Backoff(base=1.0, factor=2.0, cap=10.0)
        self.assertEqual(b.next_delay(), 1.0)
        self.assertEqual(b.next_delay(), 2.0)
        self.assertEqual(b.next_delay(), 4.0)
        self.assertEqual(b.next_delay(), 8.0)
        self.assertEqual(b.next_delay(), 10.0)
        b.reset()
        self.assertEqual(b.next_delay(), 1.0)


if __name__ == "__main__":
    unittest.main()
