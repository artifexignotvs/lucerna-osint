# Changelog

## 0.2.0

- Reject special files and no-follow symlink inputs in the original HTML CLI before reading, preventing named-pipe hangs.

- Compare two saved version 1 inventories offline with `diff`.
- Report URL, host, metadata, title, and source-provenance changes in JSON or Markdown.
- Validate bounded saved reports and reject duplicate fields, inconsistent counts,
  unsupported schemas, unsafe text, and reintroduced URL secrets.
- Keep the original extraction interface and inventory schema unchanged.
- Add changed, unchanged, malformed, special-file, privacy, and CLI regression cases.

## 0.1.0

- Offline HTML link inventories with source hashes, line references, and URL data minimization.
