"""The open-appsec model as the agent reads it (waap.data -> "waap_scores") and its score, computed as the agent
computes it. Reference (open-appsec, components/security_apps/waap/waap_clib):
  ScoreBuilder.h    KeywordData {false_positives, true_positives, score, type, coef, special_links},
                    KeywordsStats {false_positives, true_positives, intercept, log_nnz_coef}: intercept present ->
                    the linear (logistic regression) model; its "score" of a keyword is new_score
                    waap_scores version 1: {"version": 1, "scorePools": [{"key": pool, "value": scores}]}; the
                    pools are base_scores and headers_scores. A missing pool falls back to the base pool only
                    partly (types do not), so both are written, the same.
  WaapScores.cc     calcLogisticRegressionScore: 10 * expit(intercept + log_nnz_coef * log(n + 1) + sum(coef)),
                    n = number of keywords and combinations of the value; a keyword missing from the model has
                    coef 0.3, a combination 0.8; an adjacent pair of type 3 (special combination) always 0.8; a
                    pair with score 0 and coef 0 counts as missing
Strings: the feature dump (openappsec/agent, NginxionS) writes every byte >= 0x7f as \\u00XX, so a feature here is the byte
string of the agent decoded as latin-1. waap.data holds UTF-8 JSON strings.
"""

import json
import math

DEFAULT_KEYWORD_COEF = 0.3
DEFAULT_COMBI_COEF = 0.8
TYPE_KEYWORD, TYPE_COMBINATION, TYPE_SPECIAL = 1, 2, 3
POOLS = ("base_scores", "headers_scores")


def from_waap(key):
    """a key of waap.data (UTF-8 string) -> the byte string of the agent as latin-1 (the dump's form)"""
    return key.encode("utf-8").decode("latin-1")


def to_waap(feature):
    """the dump's form -> a key of waap.data; None when the bytes are not UTF-8 (JSON cannot carry them)"""
    try:
        return feature.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return None


class Model:
    """The scores of one pool: {feature: entry}, intercept, log_nnz_coef (None: not a linear model)."""

    def __init__(self, entries=None, stats=None):
        self.entries = entries or {}
        self.stats = stats or {"false_positives": 0, "true_positives": 0}

    @property
    def linear(self):
        return "intercept" in self.stats

    @classmethod
    def from_scores(cls, scores):
        if "scorePools" in scores:
            pools = {p["key"]: p["value"] for p in scores["scorePools"]}
            scores = pools["base_scores"]
        entries = {from_waap(item["key"]): dict(item["value"]) for item in scores["keyword_data"]}
        return cls(entries, dict(scores["keyword_stats"]))

    def to_scores(self):
        data = []
        for feature, value in sorted(self.entries.items()):
            key = to_waap(feature)
            if key is not None:
                data.append({"key": key, "value": value})
        pool = {"keyword_data": data, "keyword_stats": self.stats}
        return {"version": 1, "scorePools": [{"key": name, "value": pool} for name in POOLS]}

    def type_of(self, feature):
        return self.entries.get(feature, {}).get("type", 0)

    def coef(self, feature, combination):
        """the coefficient the agent uses for a feature of a value (WaapScores.cc)"""
        entry = self.entries.get(feature)
        if combination:
            if entry is not None and entry.get("type") == TYPE_SPECIAL:
                return DEFAULT_COMBI_COEF
            score = entry.get("new_score" if self.linear else "score", 0) if entry is not None else 0
            if entry is None or (score == 0 and entry.get("coef", 0) == 0):
                return DEFAULT_COMBI_COEF
            return entry.get("coef", 0.0)
        if entry is None:
            return DEFAULT_KEYWORD_COEF
        return entry.get("coef", 0.0)

    def log_odds(self, keywords, combinations):
        z = self.stats.get("intercept", 0.0)
        z += self.stats.get("log_nnz_coef", 0.0) * math.log(len(keywords) + len(combinations) + 1)
        z += sum(self.coef(k, False) for k in keywords)
        z += sum(self.coef(c, True) for c in combinations)
        return z

    def score(self, keywords, combinations):
        """the score of a value, 0..10, as the agent's linear model computes it"""
        return 10.0 / (1.0 + math.exp(-self.log_odds(keywords, combinations)))


def load_waap_data(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_waap_data(doc, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=True, separators=(",", ":"))


def read_dump(paths):
    """rows of the feature dump of the agent, grouped by sample id: {id: [row, ...]}"""
    rows = {}
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue  # a line cut by a stopped agent
                if row.get("sample"):
                    rows.setdefault(row["sample"], []).append(row)
    return rows
