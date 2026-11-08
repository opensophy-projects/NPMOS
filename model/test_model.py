"""Tests of the model tooling: python3 -m unittest discover -s model (numpy and scipy for the training tests)."""

import contextlib
import io
import json
import math
import random
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import datasets  # noqa: E402
import waapmodel  # noqa: E402
from waapmodel import Model  # noqa: E402

try:
    import numpy  # noqa: F401
    import scipy  # noqa: F401

    HAVE_SCIPY = True
except ImportError:
    HAVE_SCIPY = False


def kd(type_, coef=None, score=1.0, **extra):
    value = {"false_positives": 0, "true_positives": 1, "score": score, "type": type_, **extra}
    if coef is not None:
        value["coef"] = coef
        value["new_score"] = 10 / (1 + math.exp(-coef))
    return value


class WaapModelTest(unittest.TestCase):
    def test_score_is_the_agents_logistic_regression(self):
        m = Model({"<script": kd(1, 2.0), "<script alert": kd(2, 1.0), "a b": kd(3, 5.0)},
                  {"false_positives": 0, "true_positives": 0, "intercept": -3.0, "log_nnz_coef": 0.5})
        self.assertTrue(m.linear)
        # known keyword, unknown keyword (0.3), known pair, special pair (always 0.8), unknown pair (0.8)
        z = -3.0 + 0.5 * math.log(5 + 1) + 2.0 + 0.3 + 1.0 + 0.8 + 0.8
        self.assertAlmostEqual(m.score(["<script", "new"], ["<script alert", "a b", "x y"]),
                               10 / (1 + math.exp(-z)))

    def test_pair_with_zero_score_and_coef_is_unknown(self):
        m = Model({"p q": {"type": 2, "score": 0, "coef": 0, "new_score": 0}}, {"intercept": 0, "log_nnz_coef": 0})
        self.assertEqual(m.coef("p q", True), waapmodel.DEFAULT_COMBI_COEF)
        # as a keyword the stored coefficient counts, even 0
        self.assertEqual(m.coef("p q", False), 0)

    def test_round_trip_and_bytes(self):
        utf8 = "й".encode().decode("latin-1")  # how the dump writes the bytes of "й"
        broken = "\xd0"  # a lone byte: not UTF-8, JSON cannot carry it
        m = Model({"<script": kd(1, 1.5, special_links=["alert("]), utf8: kd(1, 0.7), broken: kd(1, 9.0)},
                  {"false_positives": 1, "true_positives": 2, "intercept": -1.0, "log_nnz_coef": 0.1})
        scores = m.to_scores()
        self.assertEqual(scores["version"], 1)
        self.assertEqual([p["key"] for p in scores["scorePools"]], ["base_scores", "headers_scores"])
        keys = [item["key"] for item in scores["scorePools"][0]["value"]["keyword_data"]]
        self.assertIn("й", keys)
        self.assertNotIn(broken, keys)
        back = Model.from_scores(json.loads(json.dumps(scores)))
        self.assertEqual(back.entries[utf8]["coef"], 0.7)
        self.assertEqual(back.entries["<script"]["special_links"], ["alert("])
        self.assertTrue(back.linear)

    def test_stock_format_version_0(self):
        m = Model.from_scores({"keyword_data": [{"key": "\u0000", "value": kd(1)}],
                               "keyword_stats": {"false_positives": 1, "true_positives": 2}})
        self.assertFalse(m.linear)
        self.assertIn("\x00", m.entries)

    def test_read_dump_skips_cut_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "1.jsonl"
            p.write_text('{"sample":"s1","keywords":["a"],"combinations":[],"score":1}\n{"sample":"s1","keyw', "utf-8")
            self.assertEqual(len(waapmodel.read_dump([p])["s1"]), 1)


class DatasetsTest(unittest.TestCase):
    def test_site_groups(self):
        self.assertEqual(datasets.site_of("Legitimate/browsing_2024_amazon_hl.json"), "amazon")
        self.assertEqual(datasets.site_of("browsing_2024_amazon.json"), "amazon")
        self.assertEqual(datasets.site_of("browsing_2024_all_jobs.json"), "all_jobs")

    def test_get_and_post_of_a_payload_are_one_group(self):
        get, post = datasets.payload_requests("' or 1=1 --")
        self.assertEqual(datasets.payload_of(get), datasets.payload_of(post))
        self.assertEqual(post["headers"]["Content-Type"], "application/x-www-form-urlencoded")

    def test_split_is_stable(self):
        self.assertEqual(datasets.unit("split", "site:amazon"), datasets.unit("split", "site:amazon"))
        self.assertNotEqual(datasets.unit("split", "site:amazon"), datasets.unit("split", "site:ebay"))

    def test_cases(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "gzip.json").write_text(json.dumps({"label": 1, "category": "bypass", "requests": [
                {"method": "post", "url": "/x", "headers": {"A": 1}, "data": {"k": "v"}}]}), "utf-8")
            (s,) = datasets.cases(d)
            self.assertEqual((s["label"], s["method"], s["data"], s["headers"]), (1, "POST", '{"k": "v"}', {"A": "1"}))


@unittest.skipUnless(HAVE_SCIPY, "numpy and scipy are needed (model/requirements.txt)")
class TrainingCycleTest(unittest.TestCase):
    """The cycle on synthetic traffic: the stock agent's run, training, the new model's run, the gate."""

    def test_cycle(self):
        self.cycle(linear=False)

    def test_cycle_from_a_linear_base(self):
        """the base model of the image is linear (the advanced model of Check Point): the training starts from it"""
        doc = self.cycle(linear=True)
        entries = Model.from_scores(doc["waap_scores"]).entries
        # a feature the training part never shows keeps the base model's weight
        self.assertEqual(entries["unseen"]["coef"], 1.25)
        self.assertNotIn("license", doc.get("waap_scores", {}))
        self.assertEqual(doc["license"], "terms")

    def cycle(self, linear):
        import evaluate
        import train

        rng = random.Random(1)
        attack_kw = ["<script", "alert(", "union", "select", "../", "/etc/passwd"]
        benign_kw = ["select", "or", "--", "'", "../"]
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            base = {"model_version": "Simple model, V1.0", "waap_signatures": {"x": 1}, "waap_scores": {
                "keyword_data": [{"key": k, "value": kd(1, score=5.0)} for k in set(attack_kw + benign_kw)]
                + [{"key": "union select", "value": kd(3, score=9.0)}],
                "keyword_stats": {"false_positives": 10, "true_positives": 20}}}
            if linear:
                base = {"model_version": "Advanced model, V2.0", "license": "terms", "waap_signatures": {"x": 1},
                        "waap_scores": {"version": 1, "scorePools": [{"key": "base_scores", "value": {
                            "keyword_data": [{"key": k, "value": kd(1, 0.5)} for k in set(attack_kw + benign_kw)]
                            + [{"key": "union select", "value": kd(3, 0.8)}, {"key": "unseen", "value": kd(1, 1.25)}],
                            "keyword_stats": {"false_positives": 10, "true_positives": 20, "intercept": -2.0,
                                              "log_nnz_coef": 0.0}}}]}}
            (d / "waap.data").write_text(json.dumps(base), "utf-8")
            samples, dump, verdicts = [], [], []
            for i in range(600):
                label = 1 if i % 3 == 0 else 0
                sid = f"s{i:04d}"
                group = f"g{i}"
                split = "test" if datasets.unit("split", group) < 0.3 else "train"
                samples.append({"id": sid, "label": label, "split": split, "source": "synthetic",
                                "category": "c", "group": group})
                pool = attack_kw if label else benign_kw
                kws = sorted(set(rng.sample(pool, rng.randint(1, 3))))
                combos = [f"{a} {b}" for a, b in zip(kws, kws[1:])]
                # the stock model: blocks on any two keywords, also many legitimate requests
                score = 2.5 * len(kws)
                dump.append({"sample": sid, "keywords": kws, "combinations": combos, "score": score,
                             "location": "url", "pool": "base_scores"})
                verdicts.append({"id": sid, "status": 403 if score >= 5 else 200, "blocked": score >= 5})
            write = lambda p, rows: p.write_text("".join(json.dumps(r) + "\n" for r in rows), "utf-8")  # noqa: E731
            write(d / "samples.jsonl", samples)
            (d / "dump").mkdir()
            write(d / "dump" / "1.jsonl", dump)
            write(d / "stock.jsonl", verdicts)

            with contextlib.redirect_stderr(io.StringIO()):
                train.main(["--samples", str(d / "samples.jsonl"), "--dump", str(d / "dump"), "--verdicts",
                            str(d / "stock.jsonl"), "--base", str(d / "waap.data"), "--name", "test",
                            "--out", str(d / "out")])
            doc = json.loads((d / "out" / "waap.data").read_text("utf-8"))
            self.assertEqual(doc["model_version"], "NginxionS test")
            self.assertEqual(doc["waap_signatures"], {"x": 1})
            card = json.loads((d / "out" / "model-card.json").read_text("utf-8"))
            self.assertAlmostEqual(card["threshold"]["max_score"], 5.0)
            self.assertEqual(card["threshold"]["explains_stock_verdicts"], 1.0)
            special = [i for i in doc["waap_scores"]["scorePools"][0]["value"]["keyword_data"]
                       if i["key"] == "union select"]
            self.assertEqual(special[0]["value"]["coef"], waapmodel.DEFAULT_COMBI_COEF)

            # the new model's run: the agent scores with the new model (as patch 0005 would dump it)
            model = Model.from_scores(doc["waap_scores"])
            t = card["threshold"]["max_score"]
            dump2, verdicts2 = [], []
            for r in dump:
                score = model.score(r["keywords"], r["combinations"])
                dump2.append({**r, "score": round(score, 6)})
                verdicts2.append({"id": r["sample"], "status": 200, "blocked": score >= t})
            (d / "dump2").mkdir()
            write(d / "dump2" / "1.jsonl", dump2)
            write(d / "new.jsonl", verdicts2)
            args = ["--samples", str(d / "samples.jsonl"), "--stock", str(d / "stock.jsonl"), "--candidate",
                    str(d / "new.jsonl"), "--dump", str(d / "dump2"), "--stock-dump", str(d / "dump"), "--model", str(d / "out" / "waap.data"),
                    "--card", str(d / "out" / "model-card.json"), "--out", str(d / "metrics.json")]
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as ok:
                evaluate.main(args)
            result = json.loads((d / "metrics.json").read_text("utf-8"))
            self.assertEqual(ok.exception.code, 0, result["checks"])
            self.assertEqual(result["parity"]["share"], 1.0)
            self.assertGreater(result["candidate"]["balanced_accuracy"], result["stock"]["balanced_accuracy"])

            # an agent that reads the model differently fails the gate, whatever the numbers
            write(d / "dump2" / "1.jsonl", [{**r, "score": r["score"] / 2} for r in dump2])
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as bad:
                evaluate.main(args)
            self.assertEqual(bad.exception.code, 1)
            return doc


if __name__ == "__main__":
    unittest.main()
