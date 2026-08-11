import unittest

from aegis_attacker.rate_limit import (
    REQUEST_BURST,
    Backoff,
    RateLimiter,
    TokenBucket,
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
        # 버스트 20까지 즉시 허용
        for _ in range(20):
            self.assertTrue(b.try_acquire())
        # 21번째는 거부(토큰 없음)
        self.assertFalse(b.try_acquire())

    def test_refill_over_time(self):
        clk = FakeClock()
        b = TokenBucket(rate=10.0, capacity=20, clock=clk)
        for _ in range(20):
            b.try_acquire()
        self.assertFalse(b.try_acquire())
        clk.advance(1.0)  # 1초 → 10 토큰 회복
        for _ in range(10):
            self.assertTrue(b.try_acquire())
        self.assertFalse(b.try_acquire())

    def test_refill_capped_at_capacity(self):
        clk = FakeClock()
        b = TokenBucket(rate=10.0, capacity=20, clock=clk)
        clk.advance(100.0)  # 아무리 지나도 상한 20
        for _ in range(20):
            self.assertTrue(b.try_acquire())
        self.assertFalse(b.try_acquire())

    def test_wait_time(self):
        clk = FakeClock()
        b = TokenBucket(rate=10.0, capacity=1, clock=clk)
        self.assertEqual(b.wait_time(), 0.0)
        b.try_acquire()
        self.assertAlmostEqual(b.wait_time(), 0.1, places=6)  # 1/10s


class TestSubmitRate(unittest.TestCase):
    def test_30_per_minute(self):
        clk = FakeClock()
        rl = RateLimiter(clock=clk)
        # 버스트 30까지 허용
        for _ in range(30):
            self.assertTrue(rl.try_submit())
        self.assertFalse(rl.try_submit())  # 31번째 거부
        clk.advance(60.0)  # 1분 → 30 회복(상한)
        for _ in range(30):
            self.assertTrue(rl.try_submit())
        self.assertFalse(rl.try_submit())


class TestRequestRate(unittest.TestCase):
    def test_shared_global_limit(self):
        clk = FakeClock()
        rl = RateLimiter(clock=clk)
        allowed = sum(1 for _ in range(100) if rl.try_request())
        self.assertEqual(allowed, REQUEST_BURST)  # 병렬이라도 전역 버스트 20 공유

    def test_acquire_blocks_until_available(self):
        clk = FakeClock()
        slept = []

        def fake_sleep(dt):
            slept.append(dt)
            clk.advance(dt)  # 잠들면 시간이 흐른다

        rl = RateLimiter(clock=clk, sleep=fake_sleep)
        for _ in range(20):
            rl.try_request()
        # 버킷 소진 상태에서 blocking acquire → sleep 후 성공
        rl.acquire_request()
        self.assertTrue(len(slept) >= 1)


class TestBackoff(unittest.TestCase):
    def test_exponential_with_cap_and_reset(self):
        b = Backoff(base=1.0, factor=2.0, cap=10.0)
        self.assertEqual(b.next_delay(), 1.0)
        self.assertEqual(b.next_delay(), 2.0)
        self.assertEqual(b.next_delay(), 4.0)
        self.assertEqual(b.next_delay(), 8.0)
        self.assertEqual(b.next_delay(), 10.0)  # cap
        self.assertEqual(b.next_delay(), 10.0)
        b.reset()
        self.assertEqual(b.next_delay(), 1.0)


if __name__ == "__main__":
    unittest.main()
