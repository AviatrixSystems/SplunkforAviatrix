#!/usr/bin/env python3
"""Smoke-test every dashboard search against a live Splunk.

Extracts each data source from the generated views (chains resolved onto their
base search, tokens set to their input defaults, or overridden with --token),
runs it through the export endpoint, and reports errors, empty results and
run time. Catches the panels that would render as "No results" or an error.

    python3 tools/dashboards/test_searches.py --earliest 1793232000 --latest 1793836800
    python3 tools/dashboards/test_searches.py --view traffic_analysis --earliest -1y

Auth: --url https://host:8089 with --user/--password, or --web http://host:8000
for a Splunk Web session (free-license instances have no login).
"""
import argparse
import csv
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

VIEWS = os.path.join(os.path.dirname(__file__), "..", "..", "aviatrix-security", "default", "data", "ui", "views")


def load(view):
    xml = open(os.path.join(VIEWS, f"{view}.xml")).read()
    if 'version="2"' not in xml:
        return None
    return json.loads(xml.split("<![CDATA[", 1)[1].split("]]>", 1)[0])


def resolve(ds, name):
    spec = ds[name]
    if spec["type"] == "ds.chain":
        return resolve(ds, spec["options"]["extend"]) + "\n" + spec["options"]["query"]
    return spec["options"]["query"]


def substitute(q, tokens):
    def rep(m):
        tok, filt = m.group(1), m.group(2)
        v = tokens.get(tok, "*")
        if filt == "|s":
            return '"' + v.replace('"', '\\"') + '"'
        return v
    return re.sub(r"\$([\w.]+)(\|[a-z])?\$", rep, q)


def labels(defn):
    out = {}
    for key, v in defn["visualizations"].items():
        for src in (v.get("dataSources") or {}).values():
            out.setdefault(src, []).append(v.get("title") or v["type"])
    for key, i in defn["inputs"].items():
        for src in (i.get("dataSources") or {}).values():
            out.setdefault(src, []).append("input: " + i.get("title", key))
    return out


class Splunk:
    def __init__(self, args):
        self.ctx = ssl._create_unverified_context()
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  urllib.request.HTTPSHandler(context=self.ctx))
        if args.web:
            self.base = args.web.rstrip("/") + "/en-US/splunkd/__raw"
            self.opener.open(args.web + "/en-US/account/login").read()
            cval = next(c.value for c in self.jar if c.name == "cval")
            data = urllib.parse.urlencode({"cval": cval, "username": args.user, "password": args.password}).encode()
            self.opener.open(args.web + "/en-US/account/login", data).read()
            self.auth = None
        else:
            self.base = args.url.rstrip("/")
            import base64
            self.auth = "Basic " + base64.b64encode(f"{args.user}:{args.password}".encode()).decode()

    def export(self, query, earliest, latest):
        params = urllib.parse.urlencode({"search": query if query.lstrip().startswith("|") else "search " + query,
                                         "earliest_time": earliest, "latest_time": latest, "output_mode": "csv"})
        # POST: Splunk 10 returns 405 for GET on the export endpoint.
        req = urllib.request.Request(f"{self.base}/services/search/jobs/export", data=params.encode())
        if not self.auth:
            key = next((c.value for c in self.jar if c.name.startswith("splunkweb_csrf_token")), "")
            req.add_header("X-Splunk-Form-Key", key)
            req.add_header("X-Requested-With", "XMLHttpRequest")
        if self.auth:
            req.add_header("Authorization", self.auth)
        return self.opener.open(req, timeout=900).read().decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--web", default=None)
    ap.add_argument("--url", default=None)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="x")
    ap.add_argument("--view", action="append")
    ap.add_argument("--earliest", default="-24h@h")
    ap.add_argument("--latest", default="now")
    ap.add_argument("--token", action="append", default=[], help="name=value")
    args = ap.parse_args()
    if not args.web and not args.url:
        ap.error("--web or --url is required")
    sp = Splunk(args)
    views = args.view or sorted(f[:-4] for f in os.listdir(VIEWS) if f.endswith(".xml"))
    failures = 0
    for view in views:
        defn = load(view)
        if not defn:
            continue
        tokens = {"time.earliest": args.earliest, "time.latest": args.latest}
        for i in defn["inputs"].values():
            o = i.get("options", {})
            if "token" in o and o["token"] != "time":
                tokens[o["token"]] = str(o.get("defaultValue", "*"))
        tokens.update(dict(t.split("=", 1) for t in args.token))
        names = labels(defn)
        ds = defn["dataSources"]
        print(f"\n=== {view}")
        for name in ds:
            if name not in names:
                continue  # base searches are exercised through their chains
            q = substitute(resolve(ds, name), tokens)
            t0 = time.time()
            try:
                body = sp.export(q, args.earliest, args.latest)
            except Exception as e:  # noqa: BLE001
                body = f"<msg type=\"ERROR\">{e}</msg>"
            dt = time.time() - t0
            errs = re.findall(r'<msg type="(?:ERROR|FATAL)">([^<]+)', body)
            rows = list(csv.reader(io.StringIO(body))) if not errs and body.strip() else []
            n = max(0, len(rows) - 1)
            status = "ERROR" if errs else ("EMPTY" if n == 0 else "ok")
            failures += status == "ERROR"
            print(f"  {status:5} {n:6} rows {dt:6.1f}s  {', '.join(names[name])[:70]}"
                  + (f"\n        {errs[0][:300]}" if errs else ""))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
