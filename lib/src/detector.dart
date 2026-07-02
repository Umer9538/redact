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
///
/// An optional [refine] callback can *trim* a greedy raw match down to the
/// valid prefix (returning `null` to reject it entirely). This is how the
/// bundled IBAN and card detectors recover when the regex over-matches into an
/// adjacent word or number: the trailing junk is stripped group by group until
/// the checksum passes, instead of discarding the whole span.
///
/// Rejected candidates never blackhole their span: scanning resumes just past
/// the rejected match's start, so shorter or later candidates inside it are
/// still considered.
class PatternDetector implements Detector {
  /// Creates a detector that emits a [PiiMatch] of [type] for each match of
  /// [pattern] that passes the optional [refine] and [validator] steps.
  ///
  /// [label] (for [PiiType.custom] matches) must be `UPPER_SNAKE_CASE`
  /// (`[A-Z][A-Z0-9_]*`): it becomes part of the placeholder token, and other
  /// shapes would defeat the collision-seeding that protects restore.
  PatternDetector({
    required this.name,
    required this.type,
    required RegExp pattern,
    bool Function(String value)? validator,
    String? Function(String raw)? refine,
    String? label,
  })  : _pattern = pattern,
        _validator = validator,
        _refine = refine,
        _label = label {
    checkLabel(label);
  }

  /// Throws [ArgumentError] unless [label] is null or `UPPER_SNAKE_CASE`.
  static void checkLabel(String? label) {
    if (label != null && !_validLabel.hasMatch(label)) {
      throw ArgumentError.value(
        label,
        'label',
        'must be UPPER_SNAKE_CASE ([A-Z][A-Z0-9_]*) so placeholder tokens '
            'stay collision-safe',
      );
    }
  }

  static final RegExp _validLabel = RegExp(r'^[A-Z][A-Z0-9_]*$');

  @override
  final String name;

  /// The category assigned to every match this detector emits.
  final PiiType type;

  final RegExp _pattern;
  final bool Function(String value)? _validator;
  final String? Function(String raw)? _refine;
  final String? _label;

  @override
  Iterable<PiiMatch> detect(String text) sync* {
    final validator = _validator;
    final refine = _refine;
    var from = 0;
    while (from <= text.length) {
      final match = _pattern.allMatches(text, from).firstOrNull;
      if (match == null) break;
      final raw = match.group(0);
      if (raw == null || raw.isEmpty) {
        from = match.start + 1;
        continue;
      }
      // Refine may trim a greedy raw match down to a valid prefix.
      final value = refine == null ? raw : refine(raw);
      final valid = value != null &&
          value.isNotEmpty &&
          raw.startsWith(value) &&
          (validator == null || validator(value));
      if (!valid) {
        // Do not skip the whole rejected span: a valid candidate may start
        // just after it (e.g. a card that the greedy pattern bridged into an
        // adjacent number). Leading boundary assertions keep this cheap.
        from = match.start + 1;
        continue;
      }
      yield PiiMatch(
        type: type,
        value: value,
        start: match.start,
        end: match.start + value.length,
        detector: name,
        label: type == PiiType.custom ? _label : null,
      );
      from = match.start + value.length;
    }
  }
}
