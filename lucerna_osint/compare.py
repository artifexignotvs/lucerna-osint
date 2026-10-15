"""Relationes servatae sine rete comparantur; fontes numquam repetuntur."""
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from .cli import MAX_BYTES, MAX_ITEMS, normalize_url, safe_text

MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_URL = 65536
FIELDS = {"schema_version", "tool", "sha256", "bytes", "encoding", "source", "effective_base", "title", "metadata", "links", "hosts", "skipped_references", "network_requests"}
URL_FIELDS = {"url", "host", "query_removed", "fragment_removed", "credentials_removed"}
LINK_FIELDS = URL_FIELDS | {"occurrences", "tags", "lines", "relations", "external_host"}
TAGS = {"a", "area", "link", "script", "img", "iframe", "source", "video", "audio", "form"}
META = {"description", "generator", "robots", "og:title", "og:type", "og:site_name"}


def _require(condition):
    if not condition:
        raise ValueError("Invalid or unsupported saved inventory")


def _integer(value, minimum=0, maximum=MAX_ITEMS):
    _require(type(value) is int and minimum <= value <= maximum)


def _text(value, limit):
    _require(isinstance(value, str) and len(value) <= limit and safe_text(value) == value)


def _array(value):
    _require(isinstance(value, list) and len(value) <= MAX_ITEMS)


def _url(value):
    _require(isinstance(value, dict) and set(value) == URL_FIELDS)
    _text(value["url"], MAX_URL)
    normalized = normalize_url(value["url"])
    _require(normalized is not None and normalized["url"] == value["url"] and normalized["host"] == value["host"])
    _require(not any(normalized[k] for k in URL_FIELDS - {"url", "host"}))
    for key in URL_FIELDS - {"url", "host"}:
        _require(type(value[key]) is bool)


def validate_report(report):
    """Forma stricta ambiguitatem et reditum secretorum prohibet."""
    _require(isinstance(report, dict) and set(report) == FIELDS)
    _require(type(report["schema_version"]) is int and report["schema_version"] == 1 and report["tool"] == "lucerna-osint")
    _require(isinstance(report["sha256"], str) and re.fullmatch("[0-9a-f]{64}", report["sha256"]) is not None)
    _integer(report["bytes"], maximum=MAX_BYTES)
    _integer(report["skipped_references"])
    _integer(report["network_requests"], maximum=0)
    _text(report["title"], 2000)
    _text(report["encoding"], 128)
    _require(bool(report["encoding"]))
    for key in ("source", "effective_base"):
        if report[key] is not None:
            _url(report[key])
    for key in ("metadata", "links", "hosts"):
        _array(report[key])
    for item in report["metadata"]:
        _require(isinstance(item, dict) and set(item) == {"name", "content", "line"})
        _require(isinstance(item["name"], str) and item["name"] in META)
        _text(item["content"], 2000)
        _integer(item["line"], 1, MAX_BYTES + 1)
    urls, counts, total = set(), {}, 0
    for item in report["links"]:
        _require(isinstance(item, dict) and set(item) == LINK_FIELDS)
        _url({key: item[key] for key in URL_FIELDS})
        _require(item["url"] not in urls)
        urls.add(item["url"])
        _integer(item["occurrences"], 1)
        total += item["occurrences"]
        counts[item["host"]] = counts.get(item["host"], 0) + item["occurrences"]
        for key in ("tags", "lines", "relations"):
            _array(item[key])
        for tag in item["tags"]:
            _require(isinstance(tag, str) and tag in TAGS)
        for line in item["lines"]:
            _integer(line, 1, MAX_BYTES + 1)
        for relation in item["relations"]:
            _text(relation, 65536)
            _require(relation and not any(c.isspace() for c in relation))
        for key in ("tags", "lines", "relations"):
            _require(item[key] == sorted(set(item[key])))
        _require(bool(item["tags"]) and bool(item["lines"]))
        _require(len(item["lines"]) <= item["occurrences"] and len(item["tags"]) <= item["occurrences"])
        expected_external = None if report["source"] is None else item["host"] != report["source"]["host"]
        _require(item["external_host"] is expected_external)
    _require(total + report["skipped_references"] <= MAX_ITEMS)
    hosts = {}
    for item in report["hosts"]:
        _require(isinstance(item, dict) and set(item) == {"host", "occurrences"})
        _text(item["host"], 253)
        _require(item["host"] not in hosts)
        _integer(item["occurrences"], 1)
        hosts[item["host"]] = item["occurrences"]
    _require(hosts == counts)
    return report


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def load_report(path):
    """Octeti finiti leguntur; via localis in errore non redditur."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            _require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
            data = stream.read(MAX_REPORT_BYTES + 1)
        _require(len(data) <= MAX_REPORT_BYTES)
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=lambda _: _require(False))
        return validate_report(value)
    except (OSError, ValueError, UnicodeError, RecursionError, TypeError):
        raise ValueError("Cannot read a valid bounded saved inventory") from None


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _changes(before, after, key):
    left, right = ({item[key]: item for item in items} for items in (before, after))
    return {"added": [right[k] for k in sorted(right.keys() - left.keys())], "removed": [left[k] for k in sorted(left.keys() - right.keys())], "changed": [{key: k, "fields": sorted(f for f in left[k] if left[k][f] != right[k][f]), "before": left[k], "after": right[k]} for k in sorted(left.keys() & right.keys()) if left[k] != right[k]]}


def compare_reports(before, after):
    """Mutationes inventarii a mutationibus fontis discernuntur."""
    before, after = validate_report(before), validate_report(after)
    def provenance(report):
        return {"html_sha256": report["sha256"], "report_sha256": hashlib.sha256(_canonical(report)).hexdigest(), **{k: report[k] for k in ("bytes", "encoding", "source", "effective_base")}}
    def metadata(report):
        return [{"name": name, "values": [m for m in report["metadata"] if m["name"] == name]} for name in sorted({m["name"] for m in report["metadata"]})]
    result = {"schema": "lucerna-diff/v1", "before": provenance(before), "after": provenance(after), "links": _changes(before["links"], after["links"], "url"), "hosts": _changes(before["hosts"], after["hosts"], "host"), "metadata": _changes(metadata(before), metadata(after), "name"), "title": None if before["title"] == after["title"] else {"before": before["title"], "after": after["title"]}, "skipped_references": {"before": before["skipped_references"], "after": after["skipped_references"]}, "network_requests": 0}
    result["status"] = "clean" if _canonical(before) == _canonical(after) else "different"
    result["provenance_changed"] = result["before"] != result["after"]
    return result


def markdown_report(report):
    """Textus ignotus intra clausuram satis longam continetur."""
    rows = ["# Lucerna saved-report comparison", "", "Status: **" + report["status"] + "**. Network requests: 0.", "", "| Inventory | Added | Removed | Changed |", "| --- | ---: | ---: | ---: |"]
    for category in ("links", "hosts", "metadata"):
        row = report[category]
        rows.append(f"| {category} | {len(row['added'])} | {len(row['removed'])} | {len(row['changed'])} |")
    payload = json.dumps(report, indent=2, ensure_ascii=True)
    fence = "`" * max(3, 1 + max((len(m.group()) for m in re.finditer(r"`+", payload)), default=0))
    rows.extend(["", "Source hashes establish byte identity, not collection time or authorship.", "", fence + "json", payload, fence, ""])
    return "\n".join(rows)
