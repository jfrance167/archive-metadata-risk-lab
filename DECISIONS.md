# Decisions — October 5, 2026

- Build a narrow original metadata analyzer instead of adopting zipdump's broader
  extraction/password/content capabilities. No third-party application code used.
- Standard-library parser receives at most 64 KiB. Its full-directory parsing
  precedes the entry-count admission rule; no resource guarantee from that rule.
- Inspect both original and effective names. Unicode Path extra can change the
  latter in the inspected runtime, so unsupported extra fields cannot receive a
  complete no-findings result. ZIP64 value decoding stays with CPython.
- Complete means metadata checks completed within supported scope, not safe.
  Size/ratio findings use untrusted declarations. No decompressor is reachable.
- CLI errors produce nonzero statuses, including short writes and oversized
  serialized output. Output caps include newline and Unicode escaping.
- Reuse reviewed local security workflow checker and action pins. Prepare hosted
  checks without claiming their execution or permission to publish.
