import unittest

from aegis_attacker.models import Endpoint, Scenario
from aegis_attacker.planner import (
    EndpointState,
    Planner,
    parse_exploit,
)

EP = Endpoint("team2.lig.internal", 8083)


class FakeAdvisor:
    def __init__(self, exploit):
        self.exploit = exploit
        self.calls = []

    def advise_exploit(self, banner, feedback, hints, model=None):
        self.calls.append((banner, feedback, list(hints), model))
        return self.exploit


class TestParseExploit(unittest.TestCase):
    def test_valid_json(self):
        obj = parse_exploit('{"vuln":"AUTH","method":"get","path":"/admin","headers":{"X-Role":"admin"}}')
        self.assertEqual(obj["method"], "GET")  # 정규화
        self.assertEqual(obj["vuln"], "AUTH")
        self.assertEqual(obj["path"], "/admin")

    def test_json_in_prose(self):
        obj = parse_exploit('sure: {"path":"/x"} done')
        self.assertEqual(obj["path"], "/x")
        self.assertEqual(obj["vuln"], "OTHER")  # 기본값

    def test_no_path_rejected(self):
        self.assertIsNone(parse_exploit('{"vuln":"SQLI"}'))

    def test_garbage_rejected(self):
        self.assertIsNone(parse_exploit("no json here"))
        self.assertIsNone(parse_exploit(""))

    def test_bad_method_defaults_get(self):
        self.assertEqual(parse_exploit('{"path":"/x","method":"DELETE"}')["method"], "GET")


class TestPlanner(unittest.TestCase):
    def test_plan_from_advice(self):
        advisor = FakeAdvisor({"vuln": "AUTH", "method": "GET", "path": "/admin",
                               "headers": {"Cookie": "session=x"}, "reason": "role escalate"})
        planner = Planner(advisor)
        state = EndpointState(EP)
        plan = planner.plan_next(EP, "Admin Portal /login /admin", "", state)
        self.assertEqual(plan.target, EP)
        self.assertEqual(plan.args["path"], "/admin")
        self.assertEqual(plan.scenario, Scenario.S1)  # AUTH → S1
        self.assertEqual(plan.reason, "role escalate")

    def test_no_advice_returns_none(self):
        planner = Planner(FakeAdvisor(None))
        self.assertIsNone(planner.plan_next(EP, "banner", "", EndpointState(EP)))

    def test_advisor_receives_hints(self):
        advisor = FakeAdvisor({"path": "/x"})
        Planner(advisor).plan_next(EP, "Shop /product?id=<n> SQLite", "", EndpointState(EP))
        _, _, hints, _ = advisor.calls[0]
        self.assertTrue(len(hints) >= 1)

    def test_should_stop_after_max_turns(self):
        planner = Planner(FakeAdvisor({"path": "/x"}), max_turns=3)
        state = EndpointState(EP)
        state.turn = 3
        self.assertTrue(planner.should_stop(state))
        state.turn = 2
        self.assertFalse(planner.should_stop(state))


if __name__ == "__main__":
    unittest.main()
