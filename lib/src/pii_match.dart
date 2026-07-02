import 'pii_type.dart';

/// A single span of detected PII within a source string.
///
/// The span is the half-open range `[start, end)` measured in UTF-16 code units
/// (the same units Dart's [String] indexing and [RegExpMatch] use), so
/// `text.substring(start, end) == value`.
class PiiMatch implements Comparable<PiiMatch> {
  /// Creates a match spanning `[start, end)` of the source text.
  const PiiMatch({
    required this.type,
    required this.value,
    required this.start,
    required this.end,
    this.detector,
    this.label,
  })  : assert(start >= 0, 'start must be non-negative'),
        assert(end > start, 'end must be greater than start');

  /// The category of PII this span represents.
  final PiiType type;

  /// The exact matched substring of the source text.
  final String value;

  /// Start offset (inclusive) in UTF-16 code units.
  final int start;

  /// End offset (exclusive) in UTF-16 code units.
  final int end;

  /// Name of the [Detector] that produced this match, for debugging and to
  /// break ties when two detectors overlap. May be null.
  final String? detector;

  /// A custom, human-readable label. Used to build placeholders for
  /// [PiiType.custom] matches; ignored for built-in types, which derive their
  /// label from [PiiType.label].
  final String? label;

  /// The number of UTF-16 code units the match spans.
  int get length => end - start;

  /// The uppercase token used to build placeholders and masks for this match.
  String get token =>
      type == PiiType.custom ? (label ?? PiiType.custom.label) : type.label;

  /// Returns a copy with the given fields replaced.
  PiiMatch copyWith({String? detector, String? label}) => PiiMatch(
        type: type,
        value: value,
        start: start,
        end: end,
        detector: detector ?? this.detector,
        label: label ?? this.label,
      );

  /// Whether this match's span overlaps [other]'s span.
  bool overlaps(PiiMatch other) => start < other.end && other.start < end;

  /// Orders matches by [start] ascending, then by longer spans first. This is
  /// the order the redactor uses when resolving overlaps and rewriting text.
  @override
  int compareTo(PiiMatch other) {
    final byStart = start.compareTo(other.start);
    if (byStart != 0) return byStart;
    return other.length.compareTo(length);
  }

  @override
  bool operator ==(Object other) =>
      other is PiiMatch &&
      other.type == type &&
      other.value == value &&
      other.start == start &&
      other.end == end &&
      other.detector == detector &&
      other.label == label;

  @override
  int get hashCode => Object.hash(type, value, start, end, detector, label);

  @override
  String toString() => 'PiiMatch(${type.name} "$value" @$start..$end)';
}
