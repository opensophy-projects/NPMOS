#!/usr/bin/env python3
"""Builds the labelled request set for training and evaluating the WAF model (docs/MODEL.md).

Sources (each request keeps its source, category and group):
  wcp-legit      legitimate.zip of the WAF Comparison Project: browsing sessions of real sites (label 0)
  wcp-malicious  malicious.zip of the WAF Comparison Project: the true positives of mgm-web-attack-payloads,
                 sent as GET ?p= and as POST p= (label 1)
  mgm-fp         false-positives.txt of mgm-web-attack-payloads: harmless text that looks like attacks, sent the
                 same two ways (label 0)
  cases          model/cases/*.json: our own requests (bypasses we met, benign traffic of our users), each with
                 its label

The split into train and test is by group, never by request: a site (all sessions of it), a payload (its GET and
POST form), a case file. The test part therefore holds sites and payloads the model has never seen: the metric is
what the model does on new traffic, not how well it remembers.

  python3 model/datasets.py --legit legitimate.zip --malicious malicious.zip --mgm <dir> --out samples.jsonl
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
import zipfile
from pathlib import Path

SEED = "nginxions-model-v1"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"


def unit(*parts):
    """A stable number in [0, 1) for the parts: the same on every run and every machine."""
    digest = hashlib.sha256("\x1f".join((SEED, *map(str, parts))).encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def site_of(name):
    """browsing_2024_amazon_hl.json -> amazon: the variants of one site stay on one side of the split."""
    stem = Path(name).stem
    stem = re.sub(r"^browsing_\d{4}_", "", stem)
    return re.sub(r"_(hl|al|ni|mu)$", "", stem)


def request(method, url, headers, data):
    return {"method": method, "url": url, "headers": headers or {}, "data": data or ""}


def payload_requests(line):
    """The two forms the WAF Comparison Project sends a payload in."""
    quoted = urllib.parse.quote(line).replace("%25", "%")
    return [
        request("GET", f"/?p={quoted}", {"User-Agent": UA}, ""),
        request("POST", "/", {"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"}, f"p={quoted}"),
    ]


def payload_of(sample):
    """The payload of a request of the malicious set (the value of p), for grouping its GET and POST form."""
    query = urllib.parse.urlsplit(sample["url"]).query if sample["method"] == "GET" else sample.get("data") or ""
    for part in str(query).split("&"):
        if part.startswith("p="):
            return part[2:]
    return json.dumps(sample, sort_keys=True)


def read_zip(path):
    """(member name, list of requests) of every JSON file of a WCP archive."""
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            with zf.open(info) as f:
                yield info.filename, json.load(f)


def legit(path, fraction):
    for name, items in read_zip(path):
        group = "site:" + site_of(name)
        for i, item in enumerate(items):
            if unit("legit", name, i) >= fraction:
                continue
            yield {"label": 0, "source": "wcp-legit", "category": Path(name).stem, "group": group, **norm(item)}


def malicious(path):
    for name, items in read_zip(path):
        category = Path(name).stem
        for item in items:
            sample = norm(item)
            yield {"label": 1, "source": "wcp-malicious", "category": category,
                   "group": f"payload:{category}:{payload_of(sample)}", **sample}


def mgm_false_positives(root):
    for path in sorted(Path(root).glob("*/false-positives.txt")):
        category = path.parent.name
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            for sample in payload_requests(line):
                yield {"label": 0, "source": "mgm-fp", "category": category, "group": f"fp:{category}:{line}",
                       **sample}


def cases(root):
    """model/cases/*.json: {"label": 0|1, "category": "...", "requests": [{method, url, headers, data}]}"""
    for path in sorted(Path(root).glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        for item in doc["requests"]:
            yield {"label": int(doc["label"]), "source": "cases", "category": doc.get("category", path.stem),
                   "group": f"case:{path.stem}", **norm(item)}


def norm(item):
    data = item.get("data") or ""
    if not isinstance(data, str):
        data = json.dumps(data)
    headers = {str(k): str(v) for k, v in (item.get("headers") or {}).items()}
    return request(str(item.get("method") or "GET").upper(), str(item.get("url") or "/"), headers, data)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--legit", help="legitimate.zip of the WAF Comparison Project")
    ap.add_argument("--legit-fraction", type=float, default=0.15,
                    help="share of the legitimate requests taken (default 0.15, like the --fast mode of the WCP)")
    ap.add_argument("--malicious", help="malicious.zip of the WAF Comparison Project")
    ap.add_argument("--mgm", help="nuclei/payloads of mgm-web-attack-payloads (its false-positives.txt are taken)")
    ap.add_argument("--cases", default=str(Path(__file__).parent / "cases"), help="our own cases (model/cases)")
    ap.add_argument("--test-fraction", type=float, default=0.3, help="share of the groups held out for the test")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    sources = []
    if args.legit:
        sources.append(legit(args.legit, args.legit_fraction))
    if args.malicious:
        sources.append(malicious(args.malicious))
    if args.mgm:
        sources.append(mgm_false_positives(args.mgm))
    if args.cases and Path(args.cases).is_dir():
        sources.append(cases(args.cases))

    counts = {}
    n = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for source in sources:
            for sample in source:
                sample["split"] = "test" if unit("split", sample["group"]) < args.test_fraction else "train"
                sample["id"] = f"s{n:07d}"
                n += 1
                key = (sample["source"], sample["split"])
                counts[key] = counts.get(key, 0) + 1
                out.write(json.dumps(sample, ensure_ascii=False) + "\n")
    for (source, split), count in sorted(counts.items()):
        print(f"{source:14} {split:5} {count}", file=sys.stderr)
    print(f"total {n}", file=sys.stderr)


if __name__ == "__main__":
    main()
