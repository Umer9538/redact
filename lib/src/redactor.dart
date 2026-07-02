import 'detector.dart';
import 'detectors.dart';
import 'pii_match.dart';
import 'pii_type.dart';
import 'redaction_result.dart';
import 'redaction_style.dart';

/// Finds and rewrites PII in text before it leaves the device.
///
/// A [Redactor] runs a set of [Detector]s over the input, resolves any overlaps
/// between them (the longest validated span wins; ties go to the earlier
/// detector in the list), and rewrites each detected value according to a
/// [RedactionStyle]. The default configuration uses
/// [Detectors.defaults] with [RedactionStyle.placeholder], producing reversible
/// output:
///
/// ```dart
/// final redactor = Redactor();
/// final result = redactor.redact('Email jane@acme.com or call 415-555-0132');
/// print(result.text); // Email [EMAIL_1] or call [PHONE_1]
/// final reply = result.restore('Sent to [EMAIL_1].'); // Sent to jane@acme.com.
/// ```
///
/// Per-category styles let you, say, keep the last four digits of a card while
/// placeholdering everything else:
///
/// ```dart
/// final redactor = Redactor(
///   styleOverrides: {PiiType.creditCard: RedactionStyle.mask},
/// );
/// ```
class Redactor {
  /// Creates a redactor.
  ///
  /// [detectors] defaults to [Detectors.defaults]. [style] is the default
  /// rewrite style; [styleOverrides] sets a style for specific [PiiType]s. A
  /// custom [replacer], if given, takes over from [style]/[styleOverrides]
  /// entirely and is treated as reversible (its tokens populate the vault) —
  /// it must therefore be *injective*: two different values (or the same value
  /// under two different indices) must never produce the same replacement, or
  /// [RedactionResult.restore] cannot tell them apart. Values listed in
  /// [allowList] are never redacted (exact match on the detected span).
  Redactor({
    List<Detector>? detectors,
    this.style = RedactionStyle.placeholder,
    Map<PiiType, RedactionStyle>? styleOverrides,
    Replacer? replacer,
    Iterable<String>? allowList,
  })  : detectors = List.unmodifiable(detectors ?? Detectors.defaults),
        styleOverrides = Map.unmodifiable(styleOverrides ?? const {}),
        allowList = Set.unmodifiable(allowList ?? const <String>{}),
        _replacer = replacer;

  /// The detectors run over the input. On overlapping matches of equal length,
  /// the detector earlier in this list wins.
  final List<Detector> detectors;

  /// The default rewrite style applied to categories without an override.
  final RedactionStyle style;

  /// Per-category style overrides.
  final Map<PiiType, RedactionStyle> styleOverrides;

  /// Detected values that are never redacted (exact match).
  final Set<String> allowList;

  final Replacer? _replacer;

  /// The effective style for [type].
  RedactionStyle styleFor(PiiType type) => styleOverrides[type] ?? style;

  /// Detects PII in [text] without rewriting anything.
  ///
  /// Returns the resolved, non-overlapping matches in order of appearance —
  /// the exact spans [redact] would rewrite. Useful for highlighting detected
  /// PII in a UI (each [PiiMatch] carries `start`/`end` offsets into [text])
  /// or for auditing without producing redacted output.
  List<PiiMatch> detect(String text) {
    final accepted = _resolve(_collect(text))..sort();
    return List.unmodifiable(accepted);
  }

  /// Detects PII in [text] and returns the rewritten text plus a reversal vault.
  RedactionResult redact(String text) {
    final accepted = detect(text); // sorted by start, then longer first

    final buffer = StringBuffer();
    final mapping = <String, String>{};
    final indices = <String, Map<String, int>>{}; // token label -> value -> idx
    final counters = <String, int>{}; // token label -> next index
    var cursor = 0;

    for (final match in accepted) {
      final perValue = indices.putIfAbsent(match.token, () => {});
      final index = perValue.putIfAbsent(
        match.value,
        () => counters[match.token] = (counters[match.token] ?? 0) + 1,
      );

      final replacer = _replacer;
      final reversible = replacer != null || styleFor(match.type).isReversible;
      final replacement = replacer != null
          ? replacer(match, index)
          : styleFor(match.type).replacement(match, index);

      buffer
        ..write(text.substring(cursor, match.start))
        ..write(replacement);
      cursor = match.end;

      if (reversible && replacement.isNotEmpty) {
        mapping[replacement] = match.value;
      }
    }
    buffer.write(text.substring(cursor));

    return RedactionResult(
      text: buffer.toString(),
      matches: List.unmodifiable(accepted),
      mapping: Map.unmodifiable(mapping),
    );
  }

  /// Convenience wrapper returning only the redacted text.
  String scrub(String text) => redact(text).text;

  /// Runs every detector, tagging each match with its detector's priority
  /// (its index in [detectors]; lower wins equal-length overlap ties).
  /// Matches whose value is in [allowList] are dropped here.
  List<(PiiMatch, int)> _collect(String text) {
    final out = <(PiiMatch, int)>[];
    for (var priority = 0; priority < detectors.length; priority++) {
      for (final match in detectors[priority].detect(text)) {
        if (allowList.contains(match.value)) continue;
        out.add((match, priority));
      }
    }
    return out;
  }

  /// Greedy interval resolution: accept the longest matches first (a longer
  /// validated span contains strictly more of the sensitive value — e.g. a
  /// full IBAN must beat a card number matched inside it), breaking ties by
  /// detector priority (earlier in [detectors] wins) and then position.
  List<PiiMatch> _resolve(List<(PiiMatch, int)> candidates) {
    candidates.sort((a, b) {
      final byLength = b.$1.length.compareTo(a.$1.length);
      if (byLength != 0) return byLength;
      final byPriority = a.$2.compareTo(b.$2);
      if (byPriority != 0) return byPriority;
      return a.$1.start.compareTo(b.$1.start);
    });

    final accepted = <PiiMatch>[];
    for (final (match, _) in candidates) {
      if (accepted.any(match.overlaps)) continue;
      accepted.add(match);
    }
    return accepted;
  }
}
