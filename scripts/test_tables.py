import unittest

import tables


def f(value, digits):
    return f"{value:.{digits}f}"


class ReportedValues(unittest.TestCase):
    def test_cost_model(self):
        c = tables.cost_model()
        self.assertEqual([f(v, 2) for v in c["prove_s"]], ["0.33", "0.30", "0.30", "0.30"])
        self.assertEqual(f(c["proof_kib"][0], 1), "339.5")
        self.assertEqual(f(c["accumulation_step_s"], 2), "1.33")

    def test_query_cost(self):
        q = tables.query_cost()
        self.assertEqual(f(q[28]["chain_proof_kib"], 1), "143.6")
        self.assertEqual(f(q[95]["chain_proof_kib"], 1), "510.3")
        self.assertEqual(f(q[28]["accumulation_over_group"], 1), "2.1")
        self.assertEqual(f(q[76]["accumulation_over_group"], 1), "4.0")
        self.assertEqual((q[28]["break_even"], q[95]["break_even"]), (69, 244))

    def test_chain(self):
        c = tables.chain()
        self.assertEqual((c["blocks"], c["transactions"], c["proof_bytes"], c["proof_sizes"]), (128, 1024, 402540, 1))
        self.assertEqual(f(c["proof_bytes"] / 1024, 1), "393.1")
        self.assertEqual(f(c["verify_ms"][0], 1), "11.6")
        self.assertEqual(f(c["accumulation_s"], 2), "2.67")
        self.assertEqual(f(c["chain_step_s"], 2), "1.35")
        self.assertEqual(f(c["group_share_pct"], 0), "14")

    def test_adversarial(self):
        self.assertEqual(tables.adversarial(), {"cases": 36, "controls": 5, "attacks": 31, "accepted": 0})

    def test_scaling(self):
        s = tables.scaling()
        self.assertEqual(f(s["group_speedup"], 2), "7.23")
        self.assertEqual(f(s["block_speedup"], 2), "2.24")
        self.assertEqual(f(s["accumulation_share_pct"], 0), "80")
        self.assertEqual(f(s["group_share_one_pct"], 0), "65")
        self.assertEqual(f(s["ceiling"], 2), "2.83")

    def test_faults(self):
        x = tables.faults()
        self.assertEqual(sum(v["runs"] for v in x.values()), 100)
        self.assertEqual(sum(v["valid"] for v in x.values()), 100)
        self.assertEqual(f(x["none"]["total_s"], 1), "16.5")
        self.assertEqual(f(x["late-duplicate"]["total_s"], 1), "54.1")

    def test_aggregation(self):
        a = tables.aggregation()
        self.assertEqual(f(a[(256, 8, 1)]["total_s"], 1), "115.7")
        self.assertEqual(f(a[(256, 8, 2)]["total_s"], 1), "114.3")
        self.assertEqual((a[(256, 8, 1)]["depth"], a[(256, 8, 2)]["depth"]), (64, 32))

    def test_budget(self):
        b = tables.budget()
        self.assertEqual([f(b[(16, g)]["online_s"][0], 2) for g in (2, 4, 8)], ["55.86", "33.18", "21.96"])
        self.assertEqual([f(b[(32, g)]["online_s"][0], 2) for g in (2, 4, 8)], ["106.06", "60.63", "38.23"])
        self.assertEqual((f(b[(16, 8)]["speedup_over_g4"], 2), f(b[(32, 8)]["speedup_over_g4"], 2)), ("1.51", "1.59"))
        self.assertEqual([f(b[(32, g)]["online_without_pause_s"], 2) for g in (2, 4, 8)], ["106.07", "60.60", "38.25"])
        self.assertEqual(f(b[(32, 8)]["online_s"][2], 2), "38.62")
        self.assertEqual((f(b[(32, 8)]["cold_s"][0], 2), f(b[(32, 8)]["cold_s"][2], 2)), ("90.97", "91.05"))
        self.assertEqual(f(b[(32, 8)]["scope_peak_gib"], 2), "2.85")
        g4 = b[(16, 4)]
        self.assertEqual((f(g4["group_s"], 2), f(g4["accumulation_s"], 2), f(g4["chain_s"], 2)),
                         ("5.15", "22.36", "5.65"))

    def test_commitment_hashing(self):
        c = tables.commitment_hashing()
        self.assertEqual([(c[g]["plain_gates"], c[g]["digest_gates"]) for g in (2, 4, 8)],
                         [(2439, 2445), (4877, 4888), (9753, 9774)])
        self.assertEqual([c[g]["degrees"] for g in (2, 4, 8)], [(12, 12), (13, 13), (14, 14)])
        self.assertTrue(all(c[g]["proof_bytes"][0] == c[g]["proof_bytes"][1] for g in (2, 4, 8)))
        self.assertEqual([[f(v, 3) for v in c[g]["digest_over_plain"]] for g in (2, 4, 8)],
                         [["0.978", "0.875", "1.156"], ["0.987", "0.938", "1.068"], ["1.005", "0.951", "1.056"]])

    def test_persistent(self):
        p = tables.persistent()
        self.assertEqual([f(p[k]["total_s"], 2) for k in ("static", "ewma", "periodic")],
                         ["184.44", "158.02", "180.31"])
        self.assertEqual([f(v, 3) for v in p["ewma"]["static_over_policy"]], ["1.167", "1.162", "1.181"])
        self.assertEqual([f(v, 3) for v in p["periodic"]["static_over_policy"]], ["1.025", "1.019", "1.025"])
        self.assertEqual(f(p["periodic"]["calibration_s"], 2), "20.23")
        self.assertEqual(p["static"]["worker0_groups"], [[3]] * 12)
        self.assertEqual(p["ewma"]["worker0_groups"][5:10], [[2], [1], [1], [1], [2]])
        self.assertEqual(p["periodic"]["worker0_groups"][9], [3])

    def test_two_host(self):
        t = tables.two_host()
        self.assertEqual([f(v, 2) for v in t[20]["maxfit_over_resource"]], ["0.90", "0.78", "0.96"])
        self.assertEqual([f(v, 2) for v in t[64]["resource_over_server"]], ["0.93", "0.91", "0.99"])
        self.assertEqual([f(v, 2) for v in t[64]["maxfit_over_resource"]], ["0.99", "0.94", "1.05"])

    def test_replay(self):
        r = tables.replay()
        self.assertEqual((f(r[256]["named_ms"], 3), f(r[256]["serial_ms"], 3), f(r[256]["parallel_ms"], 3)),
                         ("13.184", "151.187", "78.471"))
        self.assertEqual([f(v, 3) for v in r[256]["parallel_over_named"]], ["6.025", "5.078", "6.778"])
        self.assertEqual([f(v, 3) for v in r[32]["parallel_over_named"]], ["0.988", "0.780", "1.282"])

    def test_pipeline(self):
        p = tables.pipeline()
        self.assertEqual([f(p[8][k][0], 2) for k in ("leanvm_s", "pcb_block_s", "pcb_chain_s")], ["9.85", "13.64", "19.13"])
        self.assertEqual([f(p[16][k][0], 2) for k in ("leanvm_s", "pcb_block_s", "pcb_chain_s")], ["19.32", "27.58", "33.11"])

    def test_wide_area(self):
        w = tables.wide_area()
        self.assertEqual([f(v, 3) for v in w[(32, "wan-maxfit")]], ["0.989", "0.967", "1.055"])
        self.assertEqual([f(v, 3) for v in w[(32, "wan-eft")]], ["1.023", "0.964", "1.041"])
        self.assertEqual([f(v, 3) for v in w[(32, "wan-resource")]], ["1.006", "0.992", "1.075"])

    def test_same_host(self):
        s = tables.same_host()
        self.assertEqual(f(s[("PCB", 16)], 3), "1.266")
        self.assertEqual(f(s[("Winterfell Lamport+", 16)], 3), "1.312")

    def test_scheduling(self):
        s = tables.scheduling()
        self.assertEqual((s["instances"], s["closed"], s["exact"]), (720, 707, 553))
        self.assertEqual((f(s["median_gap_pct"], 2), f(s["max_gap_pct"], 1)), ("0.00", "0.9"))
        self.assertEqual(f(s["ablation"]["no-load-balancing"]["median"], 1), "4.7")
        self.assertEqual(f(s["ablation"]["no-local-search"]["max"], 1), "0.1")
        self.assertEqual(s["ablation"]["no-memory-awareness"]["infeasible"], 9)

    def test_archival(self):
        a = tables.archival()
        self.assertEqual(a["break_even"], 188)
        self.assertEqual((f(a["signature_saving_pct"], 1), f(a["total_saving_pct"], 1)), ("81.7", "78.7"))
        self.assertEqual(a["common_bytes"], 82952)


if __name__ == "__main__":
    unittest.main()
