"""Vincula et indicia ex documento locali colliguntur."""

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import re
import sys
from collections import Counter
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

MAX_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 50000


def safe_text(value):
    """Signa imperii et directionis occultae removentur."""
    return "".join(c if c.isprintable() and c not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" else " " for c in value)


def normalize_url(value, base=None):
    """Pars secreta inscriptionis numquam in relationem transit."""
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    if any(not c.isprintable() for c in value) or "\\" in value:
        return None
    try:
        parts = urlsplit(urljoin(base or "", value))
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname or "%" in parts.hostname:
            return None
        host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            ip = ipaddress.ip_address(host)
            host = str(ip)
            authority = "[" + host + "]" if ip.version == 6 else host
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                return None
            authority = host
        port = parts.port
        if port is not None and port not in ((443,) if parts.scheme == "https" else (80,)):
            authority += ":" + str(port)
        path = quote(parts.path or "/", safe="/:@!$&'()*+,;=-._~%")
        url = urlunsplit((parts.scheme.lower(), authority, path, "", ""))
        return {"url": url, "host": host, "query_removed": bool(parts.query), "fragment_removed": bool(parts.fragment), "credentials_removed": parts.username is not None or parts.password is not None}
    except (ValueError, UnicodeError):
        return None


class Page(HTMLParser):
    """Elementa statica tantum leguntur; scripta non currunt."""

    # In his elementis signa inclusa non sunt vincula.
    CDATA_CONTENT_ELEMENTS = ("script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []
        self.metadata = []
        self.base = None
        self.base_seen = False
        self.title_parts = []
        self.in_title = False
        self.title_seen = False
        self.item_count = 0

    def handle_starttag(self, tag, attrs):
        self.item_count += 1
        if self.item_count > MAX_ITEMS:
            raise ValueError("HTML element limit exceeded")
        # Primum attributum eiusdem nominis praevalet.
        values = {}
        for name, value in attrs:
            values.setdefault(name, value)
        if tag == "title" and not self.title_seen:
            self.in_title = True
            self.title_seen = True
        if tag == "base" and "href" in values and not self.base_seen:
            self.base = values["href"]
            self.base_seen = True
        fields = {"a": "href", "area": "href", "link": "href", "script": "src", "img": "src", "iframe": "src", "source": "src", "video": "src", "audio": "src", "form": "action"}
        field = fields.get(tag)
        if field and values.get(field):
            self.references.append((tag, values[field], self.getpos()[0], values.get("rel") or ""))
        if tag == "meta":
            key = (values.get("name") or values.get("property") or "").lower()
            if key in ("description", "generator", "robots", "og:title", "og:type", "og:site_name"):
                self.metadata.append({"name": key, "content": safe_text(values.get("content") or "")[:2000], "line": self.getpos()[0]})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(unescape(data))


def analyze(data, source_url=None, encoding="utf-8"):
    """Vestigium octetorum cum inventario stabili redditur."""
    if len(data) > MAX_BYTES:
        raise ValueError("Input exceeds 16 MiB")
    source = normalize_url(source_url) if source_url else None
    if source_url and source is None:
        raise ValueError("Source must be an absolute HTTP or HTTPS URL")
    try:
        text = data.decode(encoding, errors="strict")
    except (UnicodeError, LookupError):
        raise ValueError("Cannot decode input; supply the correct --encoding") from None
    page = Page()
    page.feed(text)
    page.close()
    base = (normalize_url(page.base, source_url) or source) if page.base else source
    base_url = base["url"] if base else None
    entries = {}
    skipped = 0
    for tag, raw, line, rel in page.references:
        item = normalize_url(raw, base_url)
        if item is None:
            skipped += 1
            continue
        key = item["url"]
        if key not in entries:
            entries[key] = dict(item, occurrences=0, tags=set(), lines=set(), relations=set())
        entry = entries[key]
        entry["occurrences"] += 1
        entry["tags"].add(tag)
        entry["lines"].add(line)
        entry["relations"].update(safe_text(rel).lower().split())
        for flag in ("query_removed", "fragment_removed", "credentials_removed"):
            entry[flag] = entry[flag] or item[flag]
    links = []
    for key in sorted(entries):
        entry = entries[key]
        for field in ("tags", "lines", "relations"):
            entry[field] = sorted(entry[field])
        entry["external_host"] = None if source is None else entry["host"] != source["host"]
        links.append(entry)
    counts = Counter()
    for link in links:
        counts[link["host"]] += link["occurrences"]
    return {"schema_version": 1, "tool": "lucerna-osint", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "encoding": encoding, "source": source, "effective_base": base, "title": safe_text(" ".join("".join(page.title_parts).split()))[:2000], "metadata": page.metadata, "links": links, "hosts": [{"host": host, "occurrences": counts[host]} for host in sorted(counts)], "skipped_references": skipped, "network_requests": 0}


def text_report(report):
    """Relatio ad oculos humana breviter formatur."""
    rows = ["LUCERNA · saved-page link inventory", "SHA-256: " + report["sha256"], "Title: " + report["title"], f"{len(report['links'])} distinct URLs · {len(report['hosts'])} hosts · {report['network_requests']} network requests", ""]
    for host in report["hosts"]:
        rows.append(f"{host['host']}  ({host['occurrences']} references)")
    rows.append("")
    for item in report["links"]:
        rows.append(f"{item['url']}  [lines {','.join(str(n) for n in item['lines'])}]")
    rows.append(f"Skipped references: {report['skipped_references']}")
    return "\n".join(rows)


def csv_report(report):
    """Inscriptiones absolutas forma tabulari reddit."""
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(["url", "host", "occurrences", "lines", "tags", "external_host", "query_removed", "credentials_removed"])
    for link in report["links"]:
        writer.writerow([link["url"], link["host"], link["occurrences"], ";".join(map(str, link["lines"])), ";".join(link["tags"]), link["external_host"], link["query_removed"], link["credentials_removed"]])
    return out.getvalue().rstrip("\r\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect links and metadata in a saved HTML page without network access.")
    parser.add_argument("file", help="Saved HTML file")
    parser.add_argument("--source-url", help="Original absolute URL for relative links; never fetched")
    parser.add_argument("--encoding", default="utf-8", help="Input text encoding (default: utf-8)")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    args = parser.parse_args(argv)
    try:
        with Path(args.file).open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        report = analyze(data, args.source_url, args.encoding)
    except (OSError, ValueError) as exc:
        message = "Cannot read input file" if isinstance(exc, OSError) else str(exc)
        print(json.dumps({"error": message}) if args.format == "json" else "Error: " + message, file=sys.stderr)
        return 2
    output = json.dumps(report, indent=2, ensure_ascii=True) if args.format == "json" else csv_report(report) if args.format == "csv" else text_report(report)
    print(output)
    return 0
