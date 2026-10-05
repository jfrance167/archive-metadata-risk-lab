# Learning — October 5, 2026

An entry limit after `ZipFile` construction limits accepted results, not parser
allocation: the entire central directory has already been parsed. The raw-byte
cap must precede construction.

CPython retains `orig_filename` before sanitization and can replace `filename`
through a Unicode Path extra. Both are decoded strings; neither represents the
original bytes. Checking only an effective name can hide controls such as NUL.

Initial regression: the Windows fixture writer sanitized `a\\b` to `a/b`, so
the backslash test failed without reaching its intended input. Correction patches
the small synthetic central record directly. That deliberately leaves local
headers unmatched, illustrating why metadata checks cannot establish integrity.
The initial 16-method run had one failure; corrected 21-method suite passes.

One local Ollama test-ideas request completed with 175 output tokens. Input/output
and entry-limit suggestions were useful; an extraction-oriented suggestion and
incorrect extra-field-output assumptions were rejected. Security interpretation
and reviewed code remained with Codex. No remote worker was needed.

Optional exercise: explain why a traversal finding can coexist with
`complete_metadata`, then inspect the NUL demo's original and effective names.
