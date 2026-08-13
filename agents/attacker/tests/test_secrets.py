import pickle
import unittest

from aegis_attacker.secrets import (
    KIND_FLAG,
    KIND_SUBMIT_TOKEN,
    RoundSecretStore,
    SecretError,
    SecretHandle,
)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class TestSecretStore(unittest.TestCase):
    def test_put_resolve(self):
        s = RoundSecretStore("r1")
        h = s.put(KIND_FLAG, "FLAG{secret}")
        self.assertEqual(s.resolve(h), "FLAG{secret}")
        self.assertEqual(h.kind, KIND_FLAG)

    def test_handle_hides_plaintext(self):
        s = RoundSecretStore("r1")
        h = s.put(KIND_SUBMIT_TOKEN, "tok-team1")
        self.assertNotIn("tok-team1", repr(h))
        self.assertNotIn("tok-team1", str(h))

    def test_handle_not_serializable(self):
        s = RoundSecretStore("r1")
        h = s.put(KIND_FLAG, "FLAG{x}")
        with self.assertRaises(TypeError):
            pickle.dumps(h)

    def test_expired_handle_rejected(self):
        clk = FakeClock()
        s = RoundSecretStore("r1", clock=clk, ttl=10.0)
        h = s.put(KIND_FLAG, "FLAG{x}")
        clk.advance(11.0)
        with self.assertRaises(SecretError):
            s.resolve(h)

    def test_wrong_round_rejected(self):
        s1 = RoundSecretStore("r1")
        h = s1.put(KIND_FLAG, "FLAG{x}")
        s2 = RoundSecretStore("r2")
        with self.assertRaises(SecretError):
            s2.resolve(h)

    def test_expire_all_wipes(self):
        s = RoundSecretStore("r1")
        h = s.put(KIND_FLAG, "FLAG{x}")
        s.expire_all()
        with self.assertRaises(SecretError):
            s.resolve(h)

    def test_unknown_kind_rejected(self):
        s = RoundSecretStore("r1")
        with self.assertRaises(SecretError):
            s.put("banana", "x")

    def test_snapshot_for_redaction(self):
        s = RoundSecretStore("r1")
        s.put(KIND_FLAG, "FLAG{a}")
        s.put(KIND_SUBMIT_TOKEN, "tok")
        self.assertEqual(s.secrets_snapshot(), {"FLAG{a}", "tok"})


if __name__ == "__main__":
    unittest.main()
