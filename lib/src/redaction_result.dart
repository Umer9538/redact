import 'pii_match.dart';
import 'pii_type.dart';

/// The outcome of redacting a piece of text.
///
/// [text] is the rewritten string safe to send onward. [matches] are the PII
/// spans found in the *original* input, in order of appearance and free of
/// overlaps. [mapping] is the reversal vault: it maps each reversible token
/// (produced by [RedactionStyle.placeholder] or a custom reversible replacer)
/// back to the original value, and powers [restore].
class RedactionResult {
  /// Creates a result. Usually obtained from [Redactor.redact] rather than
  /// constructed directly.
  const RedactionResult({
    required this.text,
    required this.matches,
    required this.mapping,
  });

  /// The redacted text, safe to forward to an LLM or logs.
  final String text;

  /// The PII spans detected in the original input, ordered by position.
  final List<PiiMatch> matches;

  /// Token → original value, for the reversible tokens in [text].
  final Map<String, String> mapping;

  /// Whether any PII was detected.
  bool get hasPii => matches.isNotEmpty;

  /// The number of PII spans detected.
  int get count => matches.length;

  /// The distinct PII categories detected.
  Set<PiiType> get types => {for (final m in matches) m.type};

  /// Substitutes the original values back into [input] wherever a reversible
  /// token from this redaction appears.
  ///
  /// Use it to rehydrate an LLM's reply that echoes the tokens you sent:
  ///
  /// ```dart
  /// final result = redactor.redact('Email jane@acme.com');
  /// final reply = result.restore('Done, I emailed [EMAIL_1].');
  /// // -> 'Done, I emailed jane@acme.com.'
  /// ```
  ///
  /// Tokens are replaced longest-first so an index like `[EMAIL_1]` never
  /// clobbers `[EMAIL_10]`. Only reversible styles populate [mapping]; masked,
  /// labelled, or removed values cannot be restored.
  String restore(String input) {
    if (mapping.isEmpty) return input;
    final tokens = mapping.keys.toList()
      ..sort((a, b) => b.length.compareTo(a.length));
    var output = input;
    for (final token in tokens) {
      output = output.replaceAll(token, mapping[token]!);
    }
    return output;
  }

  @override
  String toString() => 'RedactionResult($count match(es), '
      '${mapping.length} reversible)';
}
