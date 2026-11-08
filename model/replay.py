#!/usr/bin/env python3
"""Sends the requests of samples.jsonl (model/datasets.py) through the stack and writes the verdict of each.

Every request carries:
  X-Nginxions-Sample   its id: the feature dump of the agent (agent patch 0005) names the request by it;
  X-Forwarded-For  an address of its own: the training stack identifies sources by this header, so every request
                   comes from a new source. The agent weighs a score by the reputation of its source; from one
                   address the attacks of the set would lower it and the legitimate requests after them would be
                   judged by it.
Blocked = 403 (the block page of open-appsec), as in the WAF Comparison Project.

  python3 model/replay.py --samples samples.jsonl --target http://127.0.0.1:80 --host train.local --out verdicts.jsonl
"""

import argparse
import http.client
import json
import queue
import random
import sys
import threading
import time
import urllib.parse

# set by the client itself; the other headers of a sample go as they are (the agent scans them too)
SKIP = {"host", "content-length", "connection", "transfer-encoding", "x-forwarded-for", "x-nginxions-sample"}
# like requests: characters a URL may carry as they are, everything else is percent-encoded
SAFE = "!#$%&'()*+,/:;=?@[]~"


def source_ip(n):
    return f"11.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def path_of(url):
    if url.startswith(("http://", "https://")):
        parts = urllib.parse.urlsplit(url)
        url = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
    if not url.startswith("/"):
        url = "/" + url
    return urllib.parse.quote(url, safe=SAFE)


def latin1(value):
    try:
        value.encode("latin-1")
        return value
    except UnicodeEncodeError:
        return value.encode("utf-8").decode("latin-1")


class Client:
    def __init__(self, target, timeout):
        parts = urllib.parse.urlsplit(target)
        self.https = parts.scheme == "https"
        self.host = parts.hostname
        self.port = parts.port or (443 if self.https else 80)
        self.timeout = timeout
        self.conn = None

    def connect(self):
        cls = http.client.HTTPSConnection if self.https else http.client.HTTPConnection
        self.conn = cls(self.host, self.port, timeout=self.timeout)

    def send(self, sample, host, n):
        body = sample.get("data") or ""
        body = body.encode("utf-8", "surrogatepass") if body else None
        headers = [("X-Nginxions-Sample", sample["id"]), ("Host", host), ("X-Forwarded-For", source_ip(n))]
        headers += [(k, latin1(v)) for k, v in sample["headers"].items() if k.lower() not in SKIP]
        for attempt in range(3):
            try:
                if self.conn is None:
                    self.connect()
                self.conn.putrequest(sample["method"], path_of(sample["url"]), skip_host=True,
                                     skip_accept_encoding=True)
                for k, v in headers:
                    self.conn.putheader(k, v)
                if body is not None:
                    self.conn.putheader("Content-Length", str(len(body)))
                self.conn.endheaders(body)
                res = self.conn.getresponse()
                res.read()
                if res.getheader("connection", "").lower() == "close":
                    self.conn.close()
                    self.conn = None
                return res.status
            except (OSError, http.client.HTTPException) as err:
                if self.conn is not None:
                    self.conn.close()
                self.conn = None
                if attempt == 2:
                    print(f"{sample['id']}: {err}", file=sys.stderr)
                    return 0
                time.sleep(0.2 * (attempt + 1))
        return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", required=True)
    ap.add_argument("--split", choices=["all", "train", "test"], default="all")
    ap.add_argument("--target", default="http://127.0.0.1:80")
    ap.add_argument("--host", default="train.local")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    samples = []
    with open(args.samples, encoding="utf-8") as f:
        for line in f:
            s = json.loads(line)
            if args.split == "all" or s["split"] == args.split:
                samples.append(s)
    # legitimate and malicious requests mixed, the same order on every run
    random.Random(7).shuffle(samples)

    jobs = queue.Queue()
    for n, s in enumerate(samples):
        jobs.put((n, s))
    lock = threading.Lock()
    done = [0]
    started = time.monotonic()
    out = open(args.out, "w", encoding="utf-8")

    def worker():
        client = Client(args.target, args.timeout)
        while True:
            try:
                n, s = jobs.get_nowait()
            except queue.Empty:
                return
            status = client.send(s, args.host, n)
            line = json.dumps({"id": s["id"], "status": status, "blocked": status == 403}) + "\n"
            with lock:
                out.write(line)
                done[0] += 1
                if done[0] % 10000 == 0:
                    rate = done[0] / (time.monotonic() - started)
                    print(f"{done[0]}/{len(samples)} ({rate:.0f}/s)", file=sys.stderr, flush=True)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    out.close()
    failed = 0
    with open(args.out, encoding="utf-8") as f:
        failed = sum(1 for line in f if json.loads(line)["status"] == 0)
    print(f"sent {len(samples)} in {time.monotonic() - started:.0f}s, no answer: {failed}", file=sys.stderr)
    # a stack that stopped answering is not a measurement
    if failed > max(10, len(samples) // 1000):
        sys.exit(1)


if __name__ == "__main__":
    main()
