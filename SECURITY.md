# Security Policy

## Threat model — what `redact` does and does not protect against

`redact` reduces the amount of personally identifiable information that leaves
a device inside LLM prompts (or logs). It is **one layer of defense-in-depth,
not a data-loss-prevention guarantee**. Understand its boundaries before
relying on it for regulated data:

**In scope**
- Detecting *structured* PII (emails, phones, cards, SSNs/ITINs, IBANs, IPs,
  MACs, JWTs, API keys, PEM private keys) with checksum/structure validation
  to keep false positives low.
- Rewriting detected spans before text is sent onward, reversibly
  (placeholders + vault) or irreversibly (label / mask / remove).
- Deterministic behavior: same input, same output; no network calls of its
  own; no telemetry.

**Out of scope (by design)**
- Free-form PII with no validatable structure — names, street addresses,
  medical conditions written in prose. Catching those needs NER, which is
  planned as an opt-in, on-device `Detector` (see the roadmap). Until then,
  use `KeywordDetector` for values you already know (the signed-in user's
  name, for example).
- Adversarial evasion: a user who *wants* to smuggle their own PII past the
  patterns (spelling a card number out in words) can.
- Anything after the text leaves your process: the LLM provider's logging,
  caching, or training practices.

**The vault is sensitive.** Reversible redaction stores the original values in
`RedactionResult.mapping` / `RedactionSession.vault`. If you persist a session
(`toJson`), the serialized form contains the original PII — store it with the
same protection as the source data, and prefer irreversible styles when you
don't need `restore`.

## Reporting a vulnerability

If you find a detection bypass with realistic inputs (PII a documented
detector should catch but silently misses), a false-positive class that leaks
via `restore`, or any other security-relevant defect:

- Open a **private security advisory** on GitHub:
  <https://github.com/Umer9538/redact/security/advisories/new>
- Or email **muhammadumer9538@gmail.com** with subject `redact security`.

Please include a minimal reproducing input. You can expect an initial response
within 72 hours. Fixes for confirmed detection bypasses are prioritized ahead
of all feature work, and reporters are credited in the changelog unless they
prefer otherwise.
