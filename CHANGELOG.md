## 0.1.0

Initial release.

- `Redactor` — runs detectors, resolves overlaps (most specific wins), and
  rewrites PII with a chosen style.
- Reversible pipeline: `RedactionResult.restore` re-hydrates placeholder tokens
  back into an LLM's reply.
- Precision-first built-in detectors: email, phone, credit card (Luhn), US SSN,
  IBAN (mod-97), IPv4, IPv6, MAC, JWT, secrets/API keys, and opt-in URL.
- Redaction styles: `placeholder`, `label`, type-aware `mask`, `remove`, plus a
  pluggable custom replacer.
- `Detector` / `PatternDetector` extension points for domain-specific PII.
- Zero runtime dependencies; pure Dart.
