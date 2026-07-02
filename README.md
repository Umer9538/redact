# redact

[![pub package](https://img.shields.io/pub/v/redact.svg)](https://pub.dev/packages/redact)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**On-device, precision-first PII redaction for Dart and Flutter.**

Find personally identifiable information — emails, phone numbers, payment cards,
SSNs/ITINs, IBANs, IP/MAC addresses, JWTs, API keys, private keys — and rewrite
it *before* the text ever leaves the device. Send the redacted prompt to any LLM
(local or cloud), then **restore** the real values back into the model's reply.
No PII on the wire.

```dart
import 'package:redact/redact.dart';

final redactor = Redactor();

final result = redactor.redact('Email jane@acme.com or call +923001234567');
print(result.text); // Email [EMAIL_1] or call [PHONE_1]

// ...send result.text to your LLM, then rehydrate its reply:
final reply = result.restore('I have emailed [EMAIL_1].');
print(reply); // I have emailed jane@acme.com.
```

To our knowledge this is the first general-purpose PII redaction library for
Dart — the ecosystem's equivalent of Python's Presidio or LLM Guard, minus the
server and the ML runtime. (Neighboring pub.dev packages cover UI masking or
log scrubbing; none do validated detection with a reversible pipeline.)

- **Zero dependencies.** Pure Dart — works in Flutter apps, servers, and CLIs.
- **Reversible.** Placeholder tokens map back to the originals; `restore()` is
  lenient about the ways models mangle tokens (`[EMAIL\_1]`, `[email_1]`).
- **Conversation-aware.** `RedactionSession` keeps tokens consistent across a
  multi-turn chat — alice stays `[EMAIL_1]`, bob becomes `[EMAIL_2]`, and a
  reply referencing any turn restores correctly.
- **Precision-first.** Cards are Luhn-checked, IBANs pass ISO&nbsp;7064 mod-97,
  SSNs/ITINs follow the official allocation rules, IPv4 octets are
  range-checked — and greedy matches are *trimmed back* to the checksum-valid
  span rather than silently discarded.
- **Deterministic & tested.** Same input, same output. 145 tests including a
  false-positive trap corpus (dates, versions, hashes, prices, ISBNs) and
  seeded property-based round-trip fuzzing.
- **Extensible.** Custom `Detector`s, a `KeywordDetector` deny-list, an
  `allowList`, and opt-in country packs plug into the same pipeline.

## What `redact` is — and isn't

`redact` is **one layer of defense-in-depth, not a guarantee.** Pattern-based
detection is excellent at *structured* PII (things with a shape: an email, a
card, an IBAN) and deliberately conservative to keep false positives low. It
does **not** catch free-form PII such as a person's name written in prose —
that needs named-entity recognition, which is on the roadmap as a pluggable
on-device `Detector`. Use `KeywordDetector` for names you already know. Treat
redaction as risk reduction, review your policy for your data, and never rely
on it as your only control for regulated information. The full threat model is
in [SECURITY.md](SECURITY.md).

## Install

```yaml
dependencies:
  redact: ^0.1.0
```

## Multi-turn conversations

Each `Redactor.redact()` call starts fresh, so in a chat, turn one's
`[EMAIL_1]` and turn two's `[EMAIL_1]` would be *different people* behind one
token — ambiguous for the model, wrong on restore. `RedactionSession` keeps
one vault for the whole conversation:

```dart
final session = RedactionSession();

session.redact('mail alice@x.com').text; // mail [EMAIL_1]
session.redact('mail bob@x.com').text;   // mail [EMAIL_2]  (not another _1)

session.restore('cc [EMAIL_1] and [EMAIL_2]');
// -> cc alice@x.com and bob@x.com
```

Sessions serialize (`toJson` / `RedactionSession.fromJson`) so a conversation
can survive app restarts. **The serialized vault contains the original PII by
design** — store it as carefully as the data itself.

## What it detects

| Category | `PiiType` | How false positives are kept low |
| --- | --- | --- |
| Email | `email` | Address shape; asset filenames (`logo@2x.png`) rejected |
| Phone | `phone` | E.164 or separated groups, 7–15 digits; date shapes, year ranges, ISBN-like groupings rejected |
| Payment card | `creditCard` | **Luhn** checksum, 13–19 digits, consistent grouping |
| US SSN | `ssn` | SSA allocation rules (invalid area/group/serial rejected) |
| US ITIN | `itin` | `9xx` area + IRS-assigned group ranges |
| IMEI | `imei` | **Luhn** checksum + `IMEI` context word |
| IBAN | `iban` | ISO 7064 **mod-97** check digits |
| IPv4 | `ipv4` | Every octet range-checked 0–255 |
| IPv6 | `ipv6` | Full, compressed, and IPv4-mapped forms matched whole |
| MAC | `macAddress` | Colon/dash hextet form |
| JWT | `jwt` | Three base64url segments beginning `eyJ` |
| Secret / API key | `secret` | Known prefixes only: AWS, Anthropic, GitHub, GitLab, Google, Slack, Stripe, OpenAI, npm, PyPI, Hugging Face, DigitalOcean, SendGrid, Twilio, Telegram — plus PEM private-key blocks |
| URL | `url` | **Opt-in** (`Detectors.all`) — off by default |

Where a greedy pattern could over-run into adjacent text — a card followed by
its expiry, a spaced IBAN before a short word, two phone numbers side by side —
the detector *refines* the match, trimming trailing chunks until the checksum
passes, instead of leaking the value. Every one of those cases is a regression
test.

### Country packs (opt-in)

National ID formats live in opt-in packs so the defaults stay universal:

```dart
final redactor = Redactor(
  detectors: [...DetectorPacks.pk, ...Detectors.defaults],
);
redactor.redact('CNIC 35202-1234567-1').text; // CNIC [PK_CNIC_1]
```

`pk` (Pakistan CNIC) ships today; more countries are planned.

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

Only `placeholder` (and a reversible custom replacer — which must be
*injective*: never map two values to one token) can be restored; the others
intentionally discard the original.

## Deny-lists, allow-lists, and custom detectors

```dart
final redactor = Redactor(
  detectors: [
    // Redact values you already know — the signed-in user's own name:
    KeywordDetector(keywords: ['Jane Austen'], label: 'NAME'),
    // Domain-specific PII via a pattern + optional validator:
    PatternDetector(
      name: 'mrn',
      type: PiiType.custom,
      pattern: RegExp(r'\bMRN-\d{4,8}\b'),
      label: 'PATIENT_ID',
    ),
    ...Detectors.defaults,
  ],
  // ...and values that must never be redacted:
  allowList: {'support@acme.com'},
);
```

When detectors overlap, the longest validated span wins (a full IBAN beats a
card number matched inside it); equal-length ties go to the detector earlier
in the list.

## Highlighting PII in a Flutter UI

`Redactor.detect()` returns the exact spans `redact()` would rewrite — with
`start`/`end` offsets — without changing the text. That is all a live
highlighter needs:

```dart
List<TextSpan> highlight(String text, {TextStyle? mark}) {
  final spans = <TextSpan>[];
  var cursor = 0;
  for (final m in Redactor().detect(text)) {
    if (m.start > cursor) spans.add(TextSpan(text: text.substring(cursor, m.start)));
    spans.add(TextSpan(text: m.value, style: mark)); // detected PII
    cursor = m.end;
  }
  spans.add(TextSpan(text: text.substring(cursor)));
  return spans;
}
```

## Scrub every outgoing LLM call with one interceptor

For `dio`, redact request text on the way out and restore replies on the way
back in — one place, every call:

```dart
class RedactInterceptor extends Interceptor {
  final session = RedactionSession();

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (options.data is Map && (options.data as Map)['prompt'] is String) {
      (options.data as Map)['prompt'] =
          session.scrub((options.data as Map)['prompt'] as String);
    }
    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    if (response.data is String) {
      response.data = session.restore(response.data as String);
    }
    handler.next(response);
  }
}
```

For on-device runtimes (flutter_gemma, cactus, llama_cpp_dart), wrap the call
site the same way: `session.scrub(prompt)` in, `session.restore(reply)` out.

## Performance

Deterministic benchmark (`benchmark/bench.dart`), Apple M1, Dart 3.11, AOT
(the compilation mode of a Flutter release build):

| Workload | Result |
| --- | --- |
| 500-char chat prompt (email + phone + card) | **~0.14 ms** per call |
| 500-char clean prompt | ~0.12 ms per call |
| 1 MB corpus, 2,390 PII spans across 7 types | ~267 ms → **~3.8 MB/s** |

Redaction adds well under a millisecond to a typical chat message — three to
four orders of magnitude less than the LLM call it protects.

## How it compares

| | **redact** | Presidio (Python) | LLM Guard (Python) | scrubadub (Python) |
| --- | --- | --- | --- | --- |
| Runs in Flutter / pure Dart | ✅ | ❌ | ❌ | ❌ |
| Zero dependencies | ✅ | ❌ | ❌ | ❌ |
| On-device, no service | ✅ | self-hosted service or lib | lib | lib |
| Reversible redact → restore | ✅ vault + lenient matching | ✅ encrypt/decrypt operators | ✅ vault | ❌ |
| Conversation-scoped vault | ✅ | ❌ | ✅ | ❌ |
| Checksum-validated detectors | ✅ Luhn, mod-97, SSA/IRS, octets | ✅ | partial | partial |
| NER (names in prose) | 🚧 planned, opt-in | ✅ | ✅ | via plugins |
| Country-specific IDs | 🇵🇰 + planned | 40+ recognizers | ❌ | UK-focused |

If you need heavyweight NER and 40 country recognizers today and can run
Python, use Presidio. If you ship Dart and want the detection layer *inside*
your app with no service to deploy, that's what `redact` is for.

## Why on-device

The moment raw user text hits a cloud LLM endpoint it has left your trust
boundary — logged, cached, maybe used for training. Redacting on-device means
the sensitive spans never travel. Because `redact` is pure Dart with no network
calls of its own, it works the same whether the model behind it is
`flutter_gemma` running locally or a remote API.

## Roadmap

- **On-device NER detector** (names, organisations, locations) implementing the
  same `Detector` interface — best-effort recall as a safety net, opt-in.
- **Surrogate mode**: deterministic realistic fakes (`user1@example.org`)
  instead of bracketed tokens, for models that read prose better than tokens.
- **Structure-aware `redactJson`** for tool-call payloads.
- **More country packs** (checksum-validated: Aadhaar/Verhoeff, passport MRZ)
  and crypto-wallet detection (base58check / bech32 / EIP-55).
- **Streaming redaction** for token streams.

## License

MIT © 2026 Muhammad Umer
