# redact

[![pub package](https://img.shields.io/pub/v/redact.svg)](https://pub.dev/packages/redact)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**On-device, precision-first PII redaction for Dart and Flutter.**

Find personally identifiable information — emails, phone numbers, payment cards,
SSNs, IBANs, IP/MAC addresses, JWTs, API keys — and rewrite it *before* the text
ever leaves the device. Send the redacted prompt to any LLM (local or cloud),
then **restore** the real values back into the model's reply. No PII on the wire.

```dart
import 'package:redact/redact.dart';

final redactor = Redactor();

final result = redactor.redact('Email jane@acme.com or call +1 415-555-0132');
print(result.text); // Email [EMAIL_1] or call [PHONE_1]

// ...send result.text to your LLM, then rehydrate its reply:
final reply = result.restore('I have emailed [EMAIL_1].');
print(reply); // I have emailed jane@acme.com.
```

- **Zero dependencies.** Pure Dart — works in Flutter apps, servers, and CLIs.
- **Reversible.** Placeholder tokens map back to the originals, so the model's
  answer can be re-hydrated for the user.
- **Precision-first.** Cards are Luhn-checked, IBANs pass ISO&nbsp;7064 mod-97,
  SSNs honour SSA allocation rules, IPv4 octets are range-checked — far fewer
  false positives than a bag of regexes.
- **Deterministic & testable.** Same input, same output. Easy to unit-test and
  diff, and it never makes a network call itself.
- **Extensible.** Add your own `Detector` (a medical record number, an internal
  user id, an on-device NER model) — it plugs into the same pipeline.

## What `redact` is — and isn't

`redact` is **one layer of defense-in-depth, not a guarantee.** Pattern-based
detection is excellent at *structured* PII (things with a shape: an email, a
card, an IBAN) and deliberately conservative to keep false positives low. It
does **not** catch free-form PII such as a person's name written in prose —
that needs named-entity recognition, which is on the roadmap as a pluggable
on-device `Detector`. Treat redaction as risk reduction, review your policy for
your data, and never rely on it as your only control for regulated information.

## Install

```yaml
dependencies:
  redact: ^0.1.0
```

## What it detects

| Category | `PiiType` | How false positives are kept low |
| --- | --- | --- |
| Email | `email` | RFC-ish local/domain shape with boundaries |
| Phone | `phone` | Requires `+` or separators **and** 7–15 digits |
| Payment card | `creditCard` | **Luhn** checksum, 13–19 digits |
| US SSN | `ssn` | Excludes invalid area/group/serial ranges |
| IBAN | `iban` | **mod-97** check-digit validation |
| IPv4 | `ipv4` | Every octet range-checked 0–255 |
| IPv6 | `ipv6` | Full and `::`-compressed forms |
| MAC | `macAddress` | Colon/dash hextet form |
| JWT | `jwt` | Three base64url segments beginning `eyJ` |
| Secret / API key | `secret` | Known prefixes only (AWS, GitHub, Google, Slack, Stripe, OpenAI) |
| URL | `url` | **Opt-in** (`Detectors.all`) — off by default |

The default set is `Detectors.defaults` (everything except `url`, which appears
too often in ordinary text). Use `Detectors.all` to include URLs, or pass your
own list.

## Redaction styles

Choose how detected values are rewritten — globally or per category.

| Style | Example output | Reversible? |
| --- | --- | --- |
| `placeholder` (default) | `[EMAIL_1]` | ✅ yes |
| `label` | `[EMAIL]` | ❌ no |
| `mask` | `•••• •••• •••• 1111`, `j•••@acme.com` | ❌ no |
| `remove` | *(empty)* | ❌ no |

```dart
// Keep the last four digits of cards; placeholder everything else.
final redactor = Redactor(
  styleOverrides: {PiiType.creditCard: RedactionStyle.mask},
);
```

Only `placeholder` (and a reversible custom replacer) can be restored — the
others intentionally discard the original.

## Extending detection

Implement `Detector`, or use the regex-backed `PatternDetector`, and add it to
the pipeline. Use lookaround for context you require but don't want to redact,
and an optional validator to stay precision-first.

```dart
final mrn = PatternDetector(
  name: 'mrn',
  type: PiiType.custom,
  pattern: RegExp(r'\bMRN-\d{4,8}\b'),
  label: 'PATIENT_ID',
);

final redactor = Redactor(detectors: [mrn, ...Detectors.defaults]);
redactor.redact('Patient MRN-004512').text; // Patient [PATIENT_ID_1]
```

When detectors overlap, the more specific one wins: detectors earlier in the
list take priority (that's why a valid SSN beats the generic phone matcher).

## Why on-device

The moment raw user text hits a cloud LLM endpoint it has left your trust
boundary — logged, cached, maybe used for training. Redacting on-device means
the sensitive spans never travel. Because `redact` is pure Dart with no network
calls of its own, it works the same whether the model behind it is
`flutter_gemma` running locally or a remote API.

## Roadmap

- **On-device NER detector** (names, organisations, locations) implementing the
  same `Detector` interface — best-effort recall as a safety net, opt-in.
- **Streaming redaction** for token streams.
- **Flutter middleware** wrappers for popular on-device runtimes.

## License

MIT © 2026 Muhammad Umer
