# Security reporting

Use synthetic HTML and invented URLs when describing a problem. Never include credentials, private saved pages, private configuration, or identifying collection notes in a public issue.

For a sensitive vulnerability, use this repository's private vulnerability reporting feature if it is available. If that feature is unavailable, open a minimal issue requesting a private reporting channel without disclosing the vulnerability or sensitive evidence.

Include the version, Python version, expected behavior, actual behavior, and a minimal reproducible example once a suitable reporting channel is established. A report should make clear whether the issue affects input parsing, output privacy, or another boundary.

This project is an offline inventory tool. Its reports may retain sensitive URL paths, titles, and metadata; review reports before sharing them.

Saved-report comparison validates the input schema and rejects URL credentials,
query strings, fragments, duplicate fields, and inconsistent inventory counts.
It does not authenticate report claims or sanitize arbitrary secrets in titles,
metadata, or URL paths. A report digest is a byte-comparison aid, not proof of
origin. Keep input files stable while reading them; comparisons are not a
filesystem snapshot or a collection-time attestation.
