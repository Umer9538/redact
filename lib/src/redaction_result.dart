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
  /// Matching is lenient about the ways models mangle tokens — see
  /// [restoreTokens]. Only reversible styles populate [mapping]; masked,
  /// labelled, or removed values cannot be restored.
  String restore(String input) => restoreTokens(input, mapping);

  @override
  String toString() => 'RedactionResult($count match(es), '
      '${mapping.length} reversible)';
}

/// Substitutes original values back into [input] for every token in [mapping].
///
/// This is the engine behind [RedactionResult.restore]; use it directly when
/// you keep a vault of your own (for example one persisted across turns).
///
/// Replacement happens in a single left-to-right pass, longest token first, so
/// a restored value that happens to contain token-shaped text is never itself
/// rescanned, and `[EMAIL_1]` can never clobber part of `[EMAIL_10]`.
///
/// Bracket tokens (`[EMAIL_1]`) are matched leniently, because LLMs commonly
/// mangle them in replies: escaped underscores (`[EMAIL\_1]`, a markdown
/// artifact) and case changes (`[email_1]`) are still recognised and restored.
/// Tokens from a custom replacer are matched exactly.
String restoreTokens(String input, Map<String, String> mapping) {
  if (mapping.isEmpty || input.isEmpty) return input;
  final tokens = mapping.keys.toList()
    ..sort((a, b) => b.length.compareTo(a.length));
  final pattern = RegExp(
    tokens.map(_lenientTokenPattern).join('|'),
    caseSensitive: false,
  );
  return input.replaceAllMapped(pattern, (m) {
    final raw = m.group(0)!;
    return mapping[raw] ?? mapping[_canonicalToken(raw)] ?? raw;
  });
}

final RegExp _bracketToken = RegExp(r'^\[[A-Z0-9_]+\]$');

String _lenientTokenPattern(String token) {
  if (!_bracketToken.hasMatch(token)) return RegExp.escape(token);
  final body = token
      .substring(1, token.length - 1)
      .split('')
      .map((c) => c == '_' ? r'\\?_' : RegExp.escape(c))
      .join();
  return '\\[$body\\]';
}

String _canonicalToken(String raw) => raw.replaceAll(r'\', '').toUpperCase();
