import 'pii_match.dart';
import 'pii_type.dart';

/// Finds spans of PII in text.
///
/// Implement this to add domain-specific detection (a medical record number,
/// an internal user id, an on-device NER model, …). Detectors are pure: given
/// the same input they must return the same matches, and they must not mutate
/// shared state. Offsets in the returned [PiiMatch]es are in UTF-16 code units
/// relative to the input.
///
/// Detectors do not need to resolve overlaps between each other; the [Redactor]
/// merges and de-duplicates the combined output.
abstract interface class Detector {
  /// A short, stable identifier used for debugging and overlap tie-breaking.
  String get name;

  /// Returns every PII span found in [text]. May be empty.
  Iterable<PiiMatch> detect(String text);
}

/// A [Detector] backed by a single regular expression.
///
/// The whole regex match is treated as the sensitive value, so use lookaround
/// assertions — `(?<=...)` / `(?=...)` — for surrounding context you want to
/// require but not redact. An optional [validator] can reject a syntactic match
/// that fails a semantic check (for example, a card-shaped number that fails
/// the Luhn checksum), which is how detectors stay precision-first.
class PatternDetector implements Detector {
  /// Creates a detector that emits a [PiiMatch] of [type] for each match of
  /// [pattern] that passes the optional [validator].
  const PatternDetector({
    required this.name,
    required this.type,
    required RegExp pattern,
    bool Function(String value)? validator,
    String? label,
  })  : _pattern = pattern,
        _validator = validator,
        _label = label;

  @override
  final String name;

  /// The category assigned to every match this detector emits.
  final PiiType type;

  final RegExp _pattern;
  final bool Function(String value)? _validator;
  final String? _label;

  @override
  Iterable<PiiMatch> detect(String text) sync* {
    final validator = _validator;
    for (final match in _pattern.allMatches(text)) {
      final value = match.group(0);
      if (value == null || value.isEmpty) continue;
      if (validator != null && !validator(value)) continue;
      yield PiiMatch(
        type: type,
        value: value,
        start: match.start,
        end: match.end,
        detector: name,
        label: type == PiiType.custom ? _label : null,
      );
    }
  }
}
