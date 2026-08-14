import unittest

from aegis_attacker.config import (
    DEFAULT_LLM_BASE_URL,
    DEFAULT_LLM_MODEL,
    AttackerConfig,
    ConfigError,
    load_config,
)


class TestLoadConfig(unittest.TestCase):
    def test_full_env(self):
        cfg = load_config({
            "TARGETS": "team2.lig.internal,team3.lig.internal",
            "PORTS": "80,443",
            "SUBMIT_URL": "http://10.99.50.4:4100/submit",
            "SUBMIT_TOKEN": "tok-team1",
            "LLM_BASE_URL": "http://litellm.lig.internal:4000/",
            "LLM_API_KEY": "sk-x",
        })
        self.assertEqual(cfg.targets, ("team2.lig.internal", "team3.lig.internal"))
        self.assertEqual(cfg.ports, (80, 443))
        self.assertEqual(cfg.llm_base_url, "http://litellm.lig.internal:4000")  # trailing / 제거
        self.assertEqual(cfg.llm_model, DEFAULT_LLM_MODEL)
        self.assertTrue(cfg.can_run)
        self.assertTrue(cfg.can_use_llm)
        self.assertTrue(cfg.can_submit)

    def test_targets_x_ports_enumeration(self):
        cfg = load_config({"TARGETS": "a,b", "PORTS": "1,2,3", "LLM_API_KEY": "k"})
        eps = {e.key() for e in cfg.endpoints()}
        self.assertEqual(len(eps), 6)  # 2 x 3 완전 열거
        self.assertIn("a:1", eps)
        self.assertIn("b:3", eps)

    def test_malformed_ports_rejected(self):
        with self.assertRaises(ConfigError):
            load_config({"TARGETS": "a", "PORTS": "80,abc", "LLM_API_KEY": "k"})

    def test_port_range_rejected(self):
        with self.assertRaises(ConfigError):
            load_config({"TARGETS": "a", "PORTS": "70000", "LLM_API_KEY": "k"})

    def test_missing_values_inert(self):
        # 값 누락은 예외가 아니라 inert(공격 불가)로 처리한다.
        cfg = load_config({})
        self.assertEqual(cfg.targets, ())
        self.assertEqual(cfg.ports, ())
        self.assertFalse(cfg.can_run)   # 표적 없음 → inert
        self.assertFalse(cfg.can_use_llm)
        self.assertFalse(cfg.can_submit)
        self.assertEqual(cfg.llm_base_url, DEFAULT_LLM_BASE_URL)

    def test_no_llm_key_still_runs(self):
        # 표적·포트가 있으면 LLM 키가 없어도 런타임을 가동한다(배너/recon/제출).
        cfg = load_config({"TARGETS": "a", "PORTS": "80"})
        self.assertTrue(cfg.can_run)
        self.assertFalse(cfg.can_use_llm)  # LLM 조언만 비활성

    def test_no_targets_inert(self):
        cfg = load_config({"LLM_API_KEY": "k"})
        self.assertFalse(cfg.can_run)  # 표적 없으면 inert

    def test_duplicate_targets_ports_deduped(self):
        cfg = load_config({"TARGETS": "a,a,b", "PORTS": "80,80", "LLM_API_KEY": "k"})
        self.assertEqual(cfg.targets, ("a", "b"))
        self.assertEqual(cfg.ports, (80,))

    def test_defaults(self):
        cfg = AttackerConfig()
        self.assertEqual(cfg.llm_base_url, DEFAULT_LLM_BASE_URL)
        self.assertEqual(cfg.llm_model, DEFAULT_LLM_MODEL)

    def test_concurrency_optional_with_default(self):
        self.assertEqual(load_config({}).concurrency, 8)  # 기본 8
        self.assertEqual(load_config({"ATTACK_CONCURRENCY": "4"}).concurrency, 4)
        self.assertEqual(load_config({"ATTACK_CONCURRENCY": "0"}).concurrency, 1)  # 최소 1
        self.assertEqual(load_config({"ATTACK_CONCURRENCY": "9999"}).concurrency, 32)  # 상한
        self.assertEqual(load_config({"ATTACK_CONCURRENCY": "abc"}).concurrency, 8)  # 무효→기본


if __name__ == "__main__":
    unittest.main()
