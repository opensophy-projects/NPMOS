# Request headers every browser sends (Sec-Fetch-*, Priority, client hints) are not in the list of clean headers of
# the signatures of the agent: the model takes "Sec-Fetch-Dest: style" for XSS and refuses every stylesheet Chrome
# loads. Adds the headers of waap-headers.json, with strict patterns, to the signatures (run in the source tree of
# open-appsec by deploy/openappsec/Dockerfile); another value is scanned as before.
import json

path = "components/security_apps/waap/resources/waap.data"
with open(path) as f:
    data = json.load(f)
with open("/patches/waap-headers.json") as f:
    extra = json.load(f)
headers = data["waap_signatures"]["headers_re"]
clash = sorted(set(headers) & set(extra))
if clash:
    raise SystemExit(f"waap-headers.json: already in the signatures: {clash}")
headers.update(extra)
with open(path, "w") as f:
    json.dump(data, f, indent=1)
