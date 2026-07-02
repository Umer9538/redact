import 'detector.dart';
import 'pii_match.dart';
import 'pii_type.dart';

/// A [Detector] that redacts known literal strings — a deny-list.
///
/// Useful when you already know values that must never reach the model: the
/// signed-in user's name or handle, an internal codename, an account id.
///
/// ```dart
/// final me = KeywordDetector(keywords: ['Jane Austen'], label: 'NAME');
/// final redactor = Redactor(detectors: [me, ...Detectors.defaults]);
/// redactor.redact('Jane Austen logged in').text; // [NAME_1] logged in
/// ```
///
/// Matching is case-insensitive by default and word-bounded, so a keyword
/// never fires inside a larger word.
class KeywordDetector implements Detector {
  /// Creates a deny-list detector for the given literal [keywords].
  ///
  /// Empty or whitespace-only keywords are ignored. [label] becomes the token
  /// label in redacted output (`[NAME_1]` for `label: 'NAME'`).
  KeywordDetector({
    required Iterable<String> keywords,
    this.label = 'KEYWORD',
    this.caseSensitive = false,
    this.name = 'keywords',
  }) : keywords = List.unmodifiable(
          keywords.map((k) => k.trim()).where((k) => k.isNotEmpty),
        ) {
    PatternDetector.checkLabel(label);
    _pattern = _build(this.keywords, caseSensitive: caseSensitive);
  }

  @override
  final String name;

  /// The literal strings to redact.
  final List<String> keywords;

  /// The token label used in redacted output.
  final String label;

  /// Whether keywords must match with exact case. Defaults to false.
  final bool caseSensitive;

  late final RegExp? _pattern;

  static RegExp? _build(List<String> keywords, {required bool caseSensitive}) {
    if (keywords.isEmpty) return null;
    // Longest-first so 'Jane Austen' wins over a shorter keyword 'Jane'.
    final escaped = (keywords.toList()
          ..sort((a, b) => b.length.compareTo(a.length)))
        .map(RegExp.escape)
        .join('|');
    return RegExp(
      '(?<![A-Za-z0-9])(?:$escaped)(?![A-Za-z0-9])',
      caseSensitive: caseSensitive,
    );
  }

  @override
  Iterable<PiiMatch> detect(String text) sync* {
    final pattern = _pattern;
    if (pattern == null) return;
    for (final match in pattern.allMatches(text)) {
      yield PiiMatch(
        type: PiiType.custom,
        value: match.group(0)!,
        start: match.start,
        end: match.end,
        detector: name,
        label: label,
      );
    }
  }
}
