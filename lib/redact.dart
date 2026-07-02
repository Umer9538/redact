/// On-device, precision-first PII redaction for Dart and Flutter.
///
/// `redact` finds personally identifiable information (emails, phone numbers,
/// payment cards, and more) in text and rewrites it *before* the text ever
/// leaves the device — so you can send prompts to any LLM, local or cloud,
/// without shipping raw user data. The redaction is reversible: restore the
/// real values back into the model's reply.
///
/// It is deliberately **precision-first**: the bundled detectors favour few
/// false positives over total recall. Pattern-based detection cannot catch
/// everything (free-form names, for instance, need the on-device NER detector
/// planned for a later release), so treat `redact` as one layer of
/// defense-in-depth, not a guarantee.
///
/// ```dart
/// final redactor = Redactor();
/// final result = redactor.redact('Email jane@acme.com or call 415-555-0132');
/// print(result.text); // Email [EMAIL_1] or call [PHONE_1]
///
/// // ...send result.text to an LLM, then restore its reply:
/// final reply = result.restore('I have contacted [EMAIL_1].');
/// print(reply); // I have contacted jane@acme.com.
/// ```
library;

export 'src/detector.dart';
export 'src/detectors.dart';
export 'src/pii_match.dart';
export 'src/pii_type.dart';
export 'src/redaction_style.dart';
