import unittest

from aegis_attacker.models import Endpoint
from aegis_attacker.phase_policy import (
    FairScheduler,
    allocate_budget,
    cumulative_endpoint_order,
    layer_of_port,
    layers_open,
    rounds_in_phase,
    total_rounds,
)

L1 = Endpoint("team2.lig.internal", 8080)
L2 = Endpoint("team2.lig.internal", 8082)
L3 = Endpoint("team2.lig.internal", 9090)
L4 = Endpoint("team2.lig.internal", 8410)


class TestFinalsPhaseStructure(unittest.TestCase):
    def test_round_counts_2_4_4_4(self):
        self.assertEqual([rounds_in_phase(p) for p in (1, 2, 3, 4)], [2, 4, 4, 4])

    def test_total_14_rounds(self):
        self.assertEqual(total_rounds(), 14)

    def test_cumulative_layers(self):
        self.assertEqual(layers_open(1), [1])
        self.assertEqual(layers_open(2), [1, 2])
        self.assertEqual(layers_open(4), [1, 2, 3, 4])

    def test_bad_phase_rejected(self):
        with self.assertRaises(ValueError):
            rounds_in_phase(5)
        with self.assertRaises(ValueError):
            layers_open(0)


class TestLayerOfPort(unittest.TestCase):
    def test_finals_ports(self):
        self.assertEqual(layer_of_port(8080), 1)
        self.assertEqual(layer_of_port(9000), 1)
        self.assertEqual(layer_of_port(8082), 2)
        self.assertEqual(layer_of_port(1883), 3)
        self.assertEqual(layer_of_port(8554), 3)
        self.assertEqual(layer_of_port(9090), 3)
        self.assertEqual(layer_of_port(8410), 4)
        self.assertEqual(layer_of_port(8420), 4)

    def test_unknown_port(self):
        self.assertEqual(layer_of_port(443), 0)
        self.assertEqual(layer_of_port(8083), 0)


class TestCumulativeEndpointOrder(unittest.TestCase):
    def test_phase4_starts_early_without_starving_prior_layers(self):
        ordered = cumulative_endpoint_order([L1, L2, L3, L4])
        self.assertEqual(ordered, [L4, L1, L2, L3])
        self.assertEqual(set(ordered), {L1, L2, L3, L4})

    def test_unknown_ports_preserve_input_order(self):
        first = Endpoint("team2.lig.internal", 9001)
        second = Endpoint("team2.lig.internal", 9002)
        self.assertEqual(cumulative_endpoint_order([first, second]), [first, second])

    def test_each_host_keeps_all_four_cumulative_layers(self):
        endpoints = [
            Endpoint(host, port)
            for host in ("team2.lig.internal", "team3.lig.internal")
            for port in (8080, 8082, 9090, 8410)
        ]
        ordered = cumulative_endpoint_order(endpoints)
        self.assertEqual(set(ordered), set(endpoints))
        self.assertEqual(
            [endpoint.port for endpoint in ordered[:4]],
            [8410, 8080, 8082, 9090],
        )


class TestAllocateBudget(unittest.TestCase):
    def test_even_split_min_one(self):
        b = allocate_budget([L1, L2, L3], 30)
        self.assertEqual(set(b.values()), {10})
        b2 = allocate_budget([L1, L2, L3], 2)
        self.assertEqual(set(b2.values()), {1})

    def test_empty(self):
        self.assertEqual(allocate_budget([], 10), {})


class TestFairScheduler(unittest.TestCase):
    def test_round_robin(self):
        s = FairScheduler([L1, L2, L3], per_target_budget=2)
        picks = [s.next() for _ in range(3)]
        self.assertEqual(set(picks), {L1, L2, L3})

    def test_budget_exhaustion(self):
        s = FairScheduler([L1, L2], per_target_budget=1)
        seen = []
        for _ in range(10):
            e = s.next()
            if e is None:
                break
            seen.append(e)
            s.charge(e)
        self.assertEqual(sorted(e.key() for e in seen), [L1.key(), L2.key()])
        self.assertTrue(s.all_exhausted())

    def test_new_layer_does_not_starve_old(self):
        s = FairScheduler([L1], per_target_budget=3)
        s.charge(L1)
        s.add_endpoints([L2, L3], per_target_budget=3)
        self.assertEqual(s.remaining(L1), 2)
        self.assertEqual(s.remaining(L2), 3)
        self.assertEqual(s.remaining(L3), 3)
        picks = {s.next() for _ in range(3)}
        self.assertIn(L1, picks)

    def test_boost_promising_target(self):
        s = FairScheduler([L1, L2], per_target_budget=2, boost_extra=5)
        s.boost(L1)
        self.assertEqual(s.remaining(L1), 7)
        self.assertEqual(s.remaining(L2), 2)


if __name__ == "__main__":
    unittest.main()
