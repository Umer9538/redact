## 0.1.0

Initial release.

- `Redactor` — runs detectors, resolves overlaps (longest validated span wins),
  and rewrites PII with a chosen style; `detect()` returns spans without
  rewriting (for UI highlighting and audits); `allowList` exempts known-safe
  values.
- Reversible pipeline: `RedactionResult.restore` re-hydrates placeholder tokens
  in an LLM's reply — leniently, surviving common model mangling such as
  `[EMAIL\_1]` and `[email_1]` — in a single pass that can never corrupt
  restored values or pre-existing literal tokens.
- `RedactionSession` — conversation-scoped vault for multi-turn chats: the same
  value keeps its token across calls, new values keep counting up, replies
  referencing any turn restore correctly, and sessions serialize with
  `toJson`/`fromJson`.
- Precision-first built-in detectors: email, phone (E.164 + separated forms;
  date/ISBN shapes rejected), credit card (Luhn), US SSN and ITIN (official
  allocation rules), IMEI (Luhn + context), IBAN (mod-97), IPv4, IPv6
  (including IPv4-mapped), MAC, JWT, PEM private keys, API keys for 15
  providers, and opt-in URL. Greedy over-matches are refined back to the
  checksum-valid span instead of being discarded.
- Redaction styles: `placeholder`, `label`, type-aware `mask`, `remove`, plus a
  pluggable custom replacer.
- Extension points: `Detector` / `PatternDetector` (with validator and refine
  hooks), `KeywordDetector` deny-list, and opt-in country packs
  (`DetectorPacks.pk` — Pakistan CNIC).
- Test suite includes a false-positive trap corpus and seeded property-based
  round-trip fuzzing; deterministic benchmark under `benchmark/`.
- Zero runtime dependencies; pure Dart.
