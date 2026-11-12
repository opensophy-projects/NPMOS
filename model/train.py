#!/usr/bin/env python3
"""Trains the open-appsec model of NginxionS: a sparse logistic regression over the keywords and keyword pairs the
agent itself found in each value (feature dump, openappsec/agent), in the agent's own format (waap.data, linear
model: model/waapmodel.py). docs/MODEL.md describes the whole cycle.

Input (from scripts/train-model.sh):
  samples.jsonl    the requests with labels and train/test split (model/datasets.py)
  dump/*.jsonl     what the agent with the stock model found in each value of each request
  verdicts.jsonl   what the agent with the stock model decided (model/replay.py)
  waap.data        the model of the image (the advanced model of Check Point, openappsec/agent/components/security_apps/waap/resources/waap.data):
                   signatures stay, the scores are trained; a linear base model is where the training starts (its
                   weights are the prior of L2, a feature the training part never shows keeps its weight)

Labels of values: every value of a legitimate request is legitimate. Of an attack only the value that carries it
is known to be malicious: the value the stock model scored highest is taken as the attack, the other values of
that request are left out (neither label is certain for them).

Threshold: the agent blocks a request when the final score of a value reaches the threshold of the configured
confidence; the final score also weighs the source and learning. The threshold is measured on the stock model's
run (which max score separates the blocked requests from the passed ones) and the intercept is set so that the
new model is best (balanced accuracy) at that threshold on the training part.

  python3 model/train.py --samples samples.jsonl --dump dump --verdicts verdicts.jsonl --base waap.data --out out/
"""

import argparse
import copy
import datetime
import glob
import hashlib
import io
import json
import math
import sys
import tarfile
from pathlib import Path

import numpy as np
from scipy import optimize, sparse

sys.path.insert(0, str(Path(__file__).parent))
from waapmodel import (  # noqa: E402
    DEFAULT_COMBI_COEF,
    DEFAULT_KEYWORD_COEF,
    TYPE_COMBINATION,
    TYPE_KEYWORD,
    TYPE_SPECIAL,
    Model,
    load_waap_data,
    read_dump,
    save_waap_data,
)


def load_samples(path):
    samples = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = json.loads(line)
            samples[s["id"]] = {k: s[k] for k in ("label", "split", "source", "category", "group")}
    return samples


def load_verdicts(path):
    verdicts = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            v = json.loads(line)
            verdicts[v["id"]] = v
    return verdicts


def calibrate(samples, rows, verdicts):
    """the max score of a request at which the stock agent starts to block, and how well that rule explains the
    verdicts (1.0: the verdict is exactly 'max score >= threshold')"""
    pairs = []
    for sid, v in verdicts.items():
        if v["status"] == 0 or sid not in samples:
            continue
        score = max((r["score"] for r in rows.get(sid, [])), default=0.0)
        pairs.append((score, bool(v["blocked"])))
    if not pairs:
        raise SystemExit("no verdicts of the stock model")
    pairs.sort()
    total_blocked = sum(b for _, b in pairs)
    # threshold between pairs[i-1] and pairs[i]: everything from i on is predicted blocked
    best_t, best_ok = 10.0, len(pairs) - total_blocked
    passed_ok, blocked_after = 0, total_blocked
    for i, (score, blocked) in enumerate(pairs):
        if i == 0 or score != pairs[i - 1][0]:
            ok = passed_ok + blocked_after
            if ok > best_ok:
                best_t, best_ok = score, ok
        passed_ok += not blocked
        blocked_after -= blocked
    return best_t, best_ok / len(pairs)


def logit(score):
    p = min(max(score / 10.0, 1e-9), 1 - 1e-9)
    return math.log(p / (1 - p))


class Data:
    """values of the training part as a sparse 0/1 matrix over the features, plus what the agent adds itself"""

    def __init__(self, base):
        self.base = base
        self.index = {}
        self.seen_as_keyword = set()

    def fixed(self, feature):
        return self.base.type_of(feature) == TYPE_SPECIAL

    def build(self, values):
        """values: [(keywords, combinations)] -> (X, offset, log_nnz)"""
        indptr, indices = [0], []
        offset, nnz = [], []
        for keywords, combinations in values:
            cols, off = set(), 0.0
            for f in keywords:
                self.seen_as_keyword.add(f)
            for f in [*keywords, *combinations]:
                if self.fixed(f):
                    off += DEFAULT_COMBI_COEF
                else:
                    cols.add(self.index.setdefault(f, len(self.index)))
            indices.extend(sorted(cols))
            indptr.append(len(indices))
            offset.append(off)
            nnz.append(math.log(len(keywords) + len(combinations) + 1))
        return indptr, indices, np.array(offset), np.array(nnz)

    def matrix(self, indptr, indices):
        data = np.ones(len(indices))
        return sparse.csr_matrix((data, indices, indptr), shape=(len(indptr) - 1, len(self.index)))


def fit(X, offset, nnz, y, w, l2, prior=None):
    """weighted logistic regression; params = [coef..., intercept, log_nnz_coef]; L2 on the coefficients.
    prior: the params of the base model (a linear one); the fit starts from them and L2 pulls toward them instead of
    toward 0, so what the training part does not show keeps the weights of the base model."""
    n = X.shape[1]
    p0 = np.zeros(n + 2) if prior is None else np.asarray(prior, dtype=float)

    def loss(params):
        coef, b, c = params[:n], params[n], params[n + 1]
        z = X @ coef + b + c * nnz + offset
        # log(1 + exp(-y'z)) with y' = +-1, stable
        s = np.where(y > 0, 1.0, -1.0)
        m = -s * z
        lse = np.logaddexp(0, m)
        dc, dl = coef - p0[:n], c - p0[n + 1]
        value = np.dot(w, lse) + 0.5 * l2 * (np.dot(dc, dc) + dl * dl)
        g = w * (-s) * (1.0 / (1.0 + np.exp(-m)))
        grad = np.empty_like(params)
        grad[:n] = X.T @ g + l2 * dc
        grad[n] = g.sum()
        grad[n + 1] = np.dot(g, nnz) + l2 * dl
        return value, grad

    res = optimize.minimize(loss, p0.copy(), jac=True, method="L-BFGS-B", options={"maxiter": 2000})
    if not res.success:
        print(f"optimizer: {res.message}", file=sys.stderr)
    return res.x[:n], res.x[n], res.x[n + 1]


def request_max(groups, z):
    """max log-odds of each request: groups = [(label, [row index])]"""
    return [(label, max((z[i] for i in idx), default=-math.inf)) for label, idx in groups]


def best_shift(per_request, z_t):
    """the shift of the intercept that maximizes balanced accuracy at the threshold z_t"""
    pos = sorted(m for label, m in per_request if label == 1)
    neg = sorted(m for label, m in per_request if label == 0)
    if not pos or not neg:
        return 0.0, None
    candidates = {0.0}
    for m in pos + neg:
        if math.isfinite(m):
            candidates.add(z_t - m + 1e-6)
    best = (-1.0, 0.0)
    pos_a, neg_a = np.array(pos), np.array(neg)
    for d in sorted(candidates):
        tpr = float(np.mean(pos_a + d >= z_t))
        tnr = float(np.mean(neg_a + d < z_t))
        ba = (tpr + tnr) / 2
        # on a tie the smaller shift (fewer false positives)
        if ba > best[0] + 1e-12:
            best = (ba, d)
    return best[1], best[0]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", required=True)
    ap.add_argument("--dump", required=True, help="directory of the feature dump of the stock model's run")
    ap.add_argument("--verdicts", required=True, help="verdicts of the stock model's run")
    ap.add_argument("--base", required=True, help="waap.data of the image (the model of the image: the advanced "
                    "model of Check Point; a linear base model is the start of the training)")
    ap.add_argument("--l2", type=float, default=1.0, help="L2 regularization (default 1.0)")
    ap.add_argument("--name", default=datetime.date.today().isoformat(), help="model version suffix")
    ap.add_argument("--out", required=True, help="output directory")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    samples = load_samples(args.samples)
    rows = read_dump(sorted(glob.glob(str(Path(args.dump) / "*.jsonl"))))
    verdicts = load_verdicts(args.verdicts)
    base_doc = load_waap_data(args.base)
    base = Model.from_scores(base_doc["waap_scores"])

    threshold, agreement = calibrate(samples, rows, verdicts)
    z_t = logit(threshold)
    print(f"threshold: max score {threshold:.3f} (rule explains {agreement:.2%} of the stock verdicts)",
          file=sys.stderr)

    # values of the training part and their labels
    data = Data(base)
    values, y, weight, groups = [], [], [], []
    unseen_attacks = 0
    n_pos = sum(1 for s in samples.values() if s["split"] == "train" and s["label"] == 1)
    n_neg = sum(1 for s in samples.values() if s["split"] == "train" and s["label"] == 0)
    for sid, s in samples.items():
        if s["split"] != "train":
            continue
        rs = rows.get(sid, [])
        if s["label"] == 1:
            if not rs:
                unseen_attacks += 1
                groups.append((1, []))
                continue
            top = max(rs, key=lambda r: r["score"])
            groups.append((1, [len(values)]))
            values.append((top["keywords"], top["combinations"]))
            y.append(1)
            weight.append(1.0)
        else:
            idx = []
            for r in rs:
                idx.append(len(values))
                values.append((r["keywords"], r["combinations"]))
                y.append(0)
                # every legitimate request weighs as much as an attack in total; classes balanced
                weight.append(n_pos / max(n_neg, 1) / len(rs))
            groups.append((0, idx))
    if not values:
        raise SystemExit("no values with keywords in the training part")
    indptr, indices, offset, nnz = data.build(values)
    X = data.matrix(indptr, indices)
    y, weight = np.array(y), np.array(weight)
    print(f"training: {X.shape[0]} values, {X.shape[1]} features, {int(y.sum())} attacks "
          f"({unseen_attacks} attacks without keywords: no model can see them)", file=sys.stderr)

    prior = None
    if base.linear:
        # start from the base model: its coefficient of each feature, its intercept and log_nnz_coef
        prior = [base.coef(f, f not in data.seen_as_keyword) for f in sorted(data.index, key=data.index.get)]
        prior += [base.stats.get("intercept", 0.0), base.stats.get("log_nnz_coef", 0.0)]
        print(f"start: the base model ({base_doc.get('model_version')})", file=sys.stderr)
    coef, intercept, log_nnz = fit(X, offset, nnz, y, weight, args.l2, prior)
    z = X @ coef + intercept + log_nnz * nnz + offset
    shift, train_ba = best_shift(request_max(groups, z), z_t)
    intercept += shift
    print(f"intercept {intercept:.4f} (shift {shift:+.4f}), log_nnz_coef {log_nnz:.4f}, "
          f"train balanced accuracy at the threshold {train_ba}", file=sys.stderr)

    # the model: every feature of the stock model and every feature seen in training
    model = Model(copy.deepcopy(base.entries), {
        "false_positives": base.stats.get("false_positives", 0),
        "true_positives": base.stats.get("true_positives", 0),
        "intercept": float(intercept),
        "log_nnz_coef": float(log_nnz),
    })
    learned = {f: float(coef[i]) for f, i in data.index.items()}
    for feature in set(model.entries) | set(learned):
        entry = model.entries.setdefault(feature, {
            "false_positives": 0, "true_positives": 0, "score": 0.0,
            "type": TYPE_KEYWORD if feature in data.seen_as_keyword else TYPE_COMBINATION,
        })
        if entry.get("type") == TYPE_SPECIAL:
            c = DEFAULT_COMBI_COEF
        elif feature in learned:
            c = learned[feature]
        elif base.linear and "coef" in entry:
            # never seen in training: the base model's weight stays
            c = entry["coef"]
        else:
            # never seen in training: what the agent gives a feature it does not know
            c = DEFAULT_KEYWORD_COEF if entry.get("type") == TYPE_KEYWORD else DEFAULT_COMBI_COEF
        entry["coef"] = round(c, 8)
        # the agent takes score 0 and coef 0 of a pair for "not in the model": new_score is never 0
        entry["new_score"] = round(10.0 / (1.0 + math.exp(-c)), 8) or 1e-8

    doc = copy.deepcopy(base_doc)
    doc["model_version"] = f"NginxionS {args.name}"
    doc["waap_scores"] = model.to_scores()
    waap = out / "waap.data"
    save_waap_data(doc, waap)
    with tarfile.open(out / "open-appsec-advanced-model.tgz", "w:gz") as tar:
        tar.add(waap, arcname="waap.data")

    # what the model does at the threshold on the held-out part, computed offline (the run through the agent
    # in scripts/train-model.sh is the measurement that counts)
    offline = {}
    for part in ("train", "test"):
        tp = fn = tn = fp = 0
        for sid, s in samples.items():
            if s["split"] != part:
                continue
            m = max((model.score(r["keywords"], r["combinations"]) for r in rows.get(sid, [])), default=0.0)
            hit = m >= threshold
            if s["label"] == 1:
                tp += hit
                fn += not hit
            else:
                fp += hit
                tn += not hit
        tpr = tp / max(tp + fn, 1)
        tnr = tn / max(tn + fp, 1)
        offline[part] = {"tpr": tpr, "tnr": tnr, "balanced_accuracy": (tpr + tnr) / 2, "attacks": tp + fn,
                         "legitimate": tn + fp}
    card = {
        "model_version": doc["model_version"],
        "trained": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(waap.read_bytes()).hexdigest(),
        "threshold": {"max_score": threshold, "explains_stock_verdicts": agreement},
        "training": {"values": int(X.shape[0]), "features": int(X.shape[1]), "attacks": int(y.sum()),
                     "attacks_without_keywords": unseen_attacks, "l2": args.l2},
        "params": {"intercept": float(intercept), "log_nnz_coef": float(log_nnz)},
        "offline": offline,
        "top_features": sorted(({"feature": f, "coef": round(learned[f], 4)} for f in learned),
                               key=lambda e: -abs(e["coef"]))[:40],
    }
    (out / "model-card.json").write_text(json.dumps(card, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(offline, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()
