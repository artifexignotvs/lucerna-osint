# Lucerna

**Inventory saved web pages. Compare what changed. No network access.**

Lucerna is a small OSINT triage utility for HTML evidence you already have. It extracts HTTP(S) references, groups destination hosts, records source line numbers, and hashes the original bytes. Use it to review an archived page, document external dependencies, or turn a saved research page into structured leads.

*Ex documentis, indicia.*

## Try it in a minute

Requires Python 3.10 or later. No runtime dependencies, account, API key, or installation needed from a checkout.

```sh
git clone https://github.com/artifexignotvs/lucerna-osint.git
cd lucerna-osint
python -m lucerna_osint examples/page.html --source-url https://example.org/archive/
python -m lucerna_osint examples/page.html --source-url https://example.org/archive/ --format json
python -m lucerna_osint examples/page.html --source-url https://example.org/archive/ --format csv > links.csv
```

Optional installation: `python -m pip install .` provides the `lucerna` command. The build step may obtain packaging tools; analysis itself never uses the network.

## What the report contains

- SHA-256 and byte size of the exact input file.
- Page title and a small allowlist of static metadata: description, generator, robots, and selected social preview fields.
- Unique HTTP(S) URLs, hostnames, occurrence counts, HTML tags, link relations, and line references.
- A host inventory and whether each URL's hostname differs from the supplied source hostname.
- Explicit counts for references that could not be included.

The sample produces **4 distinct URLs across 3 hosts**. Two reference URLs become one after query removal. The email link is excluded.

## Compare two saved reports

Version 0.2.0 adds offline comparison of the existing version 1 JSON inventory.
Capture each page separately, with the same source URL and encoding where possible:

```sh
python -m lucerna_osint examples/page.html --source-url https://example.org/archive/ --format json > before.json
python -m lucerna_osint examples/page-after.html --source-url https://example.org/archive/ --format json > after.json
python -m lucerna_osint diff before.json after.json --format json
python -m lucerna_osint diff before.json after.json --format markdown > comparison.md
```

The comparison reports added, removed, and changed URLs, host occurrence counts,
metadata groups, page title, and skipped-reference counts. A URL present in both
reports is changed when its counts, tags, line references, relations, or redaction
flags differ. Metadata is grouped by name, preserving repeated values and their
line references. A new path is an added URL, even when its host already existed.

The `lucerna-diff/v1` JSON result includes `before` and `after` provenance:
`html_sha256`, `report_sha256`, byte size, encoding, source URL, and effective base.
The report digest covers canonical JSON with sorted object keys, compact separators,
ASCII escapes, and no final newline. Arrays retain their supplied order.
`links`, `hosts`, and `metadata` each have `added`, `removed`, and `changed` arrays;
changed items contain `before`, `after`, and a `fields` list. A source-byte or
context change can yield `status: different` with no link changes. Comparison does
not refetch the page, verify its claimed provenance, or prove when it was collected.

Exit codes for `diff`: **0** identical saved reports, **1** differences, **2**
invalid input or a read error. Markdown contains a summary and the full safely
fenced JSON evidence. Existing `lucerna FILE` flags and output remain compatible; use `./diff` if
the HTML input itself is named `diff`.

Saved report inputs must be regular UTF-8 JSON files, at most 64 MiB, using the
exact version 1 schema. Duplicate keys/URLs/hosts, unknown fields, nonfinite values,
inconsistent host counts, unsafe text, and URLs containing credentials, queries,
or fragments are rejected. Arrays are limited to 50,000 items; URL and relation
strings to 65,536 characters, titles/metadata to 2,000, and encoding labels to 128.
HTML size and reference totals retain the original limits. Ordinary HTML inputs also require regular files; named pipes, devices and directories are rejected before reading. Symlink input files
are rejected where the platform supports no-follow opens. Keep source files
stable while reading. Malformed-report errors omit local file paths and values.

## Privacy and interpretation

URL credentials, query strings, and fragments are removed from reports. Flags record whether those parts existed. Consequently, multiple distinct original URLs can collapse to one inventory entry. This is intentional data minimization, not an exact URL archive.

**Reports can still contain sensitive URL paths, titles, and metadata. Review them before sharing.** Redaction is not a general-purpose secret detector. Source filenames and absolute local paths are not included in reports.

`--source-url` is contextual information you supply; it is never fetched or verified. The first HTML `base` element can override relative-link resolution. Hosts are compared exactly, not by registrable domain or ownership; subdomains therefore count as different hosts. Internationalized hostnames use ASCII IDNA encoding. Unicode and space characters in URL paths are percent-encoded, while existing percent escapes are preserved. URLs containing control or invisible formatting characters, backslashes, or scoped IPv6 identifiers are excluded. No DNS, WHOIS, geolocation, identity attribution, or reputation conclusions are performed.

## Boundaries

This is a static inventory, not a browser or crawler. It does not execute JavaScript, follow links, load images, parse CSS URLs, expand `srcset`, or inspect embedded documents. Dynamic links will be absent. Duplicate attributes use their first value, and markup-looking text inside title, textarea, and raw-text containers is not inventoried as links. Parsing is intentionally bounded and does not reproduce every browser error-recovery rule. Inputs are limited to 16 MiB and 50,000 HTML start tags; exceeding a limit produces an error rather than a partial report. Text decoding is strict UTF-8 by default; pass `--encoding` for another known encoding.

A hash lets you compare bytes to a trusted record. It does not prove origin, authenticity, collection time, or an unbroken chain of custody. Keep the original file and collection notes separately. Reading a file can update access timestamps depending on the filesystem.

Exit status: `0` for a completed inventory, `2` for invalid input or a read error. Reports are deterministic for the same bytes and options. JSON uses schema version 1. CSV includes link rows; JSON includes the full evidence summary.

## Development

```sh
python -m unittest discover -s tests -v
```

Tests cover evidence hashes, relative links, redaction, deduplication, malformed hosts, IPv6, encoding limits, output safety, and operation with networking disabled. Source comments and docstrings are in Latin; commands and documentation are in English.

Contributions should include a small synthetic fixture and a regression test. Useful next steps include additional explicitly documented static reference types and collection-note workflows.

MIT licensed. See [LICENSE](LICENSE).
