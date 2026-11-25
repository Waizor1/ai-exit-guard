#!/usr/bin/env python3
"""Build the offline MCP host snapshot from complete, paginated official registry listings."""
import datetime
import http.client
import ipaddress
import json
import pathlib
import re
import time
import tempfile
import urllib.parse

BASE = pathlib.Path(__file__).resolve().parents[1]
API = "registry.modelcontextprotocol.io"
META = "io.modelcontextprotocol.registry/official"
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
EXCLUDED = {"localhost", "local", "test", "invalid", "example", "internal", "lan", "corp", "onion", "arpa", "alt", "home", "localdomain"}
RESERVED = ("example.com", "example.net", "example.org", "nip.io", "sslip.io", "localtest.me", "lvh.me", "localhost.direct")
# Reviewed dedicated endpoints whose registry publisher uses a GitHub namespace.
DEDICATED = {
    "mcp.context7.com": "io.github.upstash/context7",
    "mcp.sentry.dev": "io.github.getsentry/sentry-mcp",
}


def vetted(remote, publisher):
    raw = remote.get("url", "")
    if remote.get("type") not in ("streamable-http", "sse") or not raw.isascii() or any(c in raw for c in "{}*\\") or any(c.isspace() for c in raw):
        return None
    try:
        url = urllib.parse.urlsplit(raw)
        h = url.hostname
        if not h or url.scheme != "https" or url.netloc.lower() not in (h, h + ":443"):
            return None
    except ValueError:
        return None
    labels = h.split(".")
    if len(h)>253 or len(labels)<3 or any(not LABEL.fullmatch(x) for x in labels) or not labels[-1].isalpha() or len(labels[-1])<2:
        return None
    if set(labels) & EXCLUDED or any(h==s or h.endswith("."+s) for s in RESERVED):
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    if DEDICATED.get(h)==publisher:
        return h
    namespace, sep, _ = publisher.partition("/")
    verified_domain = ".".join(reversed(namespace.lower().split(".")))
    if not sep or namespace.startswith("io.github.") or "." not in verified_domain:
        return None
    if "mcp" not in labels[:-2] or not (h==verified_domain or h.endswith("."+verified_domain)):
        return None
    return h


def collect():
    conn = http.client.HTTPSConnection(API, timeout=30)
    rows, cursors = {}, set()
    cursor = None
    count = 0
    for page in range(1,1001):
        params = {"limit":"100","version":"latest"}
        if cursor is not None:
            params["cursor"]=cursor
        path = "/v0.1/servers?"+urllib.parse.urlencode(params)
        for attempt in range(5):
            try:
                conn.request("GET",path,headers={"Accept":"application/json","User-Agent":"AIExitGuard-catalog-refresh/1"})
                resp=conn.getresponse()
                body=resp.read(8*1024*1024+1)
                if resp.status!=200 or len(body)>8*1024*1024:
                    raise ValueError("registry page rejected, HTTP %d" % resp.status)
                data=json.loads(body)
                break
            except (OSError, ValueError, http.client.HTTPException):
                conn.close()
                if attempt==4:
                    raise
                time.sleep(2**attempt)
        batch = data["servers"]
        if data["metadata"]["count"]!=len(batch):
            raise ValueError("inconsistent registry page")
        count += len(batch)
        for entry in batch:
            meta = entry.get("_meta",{}).get(META,{})
            if meta.get("status")!="active" or meta.get("isLatest") is not True:
                continue
            server=entry["server"]
            name=server["name"]
            for r in server.get("remotes",[]):
                host=vetted(r,name)
                if host:
                    rows[host]=min(name, rows.get(host,name))
        if page%20==0:
            print("pages=%d entries=%d eligible=%d" % (page,count,len(rows)),flush=True)
        cursor=data["metadata"].get("nextCursor")
        if not cursor:
            conn.close()
            return rows,page,count
        if not isinstance(cursor,str) or cursor in cursors or not batch:
            raise ValueError("invalid registry cursor")
        cursors.add(cursor)
    raise ValueError("registry traversal exceeded bound")


def main():
    rows,pages,entries=collect()
    if not 20<=len(rows)<=16384:
        raise ValueError("catalog size outside review bounds")
    hosts=sorted(rows)
    snapshot = "# Official MCP Registry v0.1, latest active servers\n# Collected %s UTC; pages %d; entries %d\n" % (datetime.datetime.now(datetime.timezone.utc).date(),pages,entries)
    snapshot += "".join(h+"\t"+rows[h]+"\n" for h in hosts)
    target = BASE / "catalog.tsv"
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=BASE, delete=False) as completed:
        completed.write(snapshot)
    pathlib.Path(completed.name).replace(target)
    print("snapshot complete: %d pages, %d entries, %d hosts" % (pages,entries,len(rows)))


if __name__=="__main__":
    main()
