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
  ///
  /// Each call starts a fresh vault: placeholder indices restart at 1 and
  /// [RedactionResult.mapping] covers only this call. For multi-turn
  /// conversations, use a [RedactionSession] so tokens stay consistent across
  /// calls.
  RedactionResult redact(String text) =>
      _redact(text, indices: {}, counters: {}, vault: {});

  /// The engine behind [redact] and [RedactionSession.redact]: rewrites [text]
  /// using (and updating) the caller's token state.
  RedactionResult _redact(
    String text, {
    required Map<String, Map<String, int>> indices, // label -> value -> idx
    required Map<String, int> counters, // label -> last index used
    required Map<String, String> vault, // token -> original value
  }) {
    final accepted = detect(text); // sorted by start, then longer first

    final buffer = StringBuffer();
    _seedCounters(text, counters);
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
        vault[replacement] = match.value;
      }
    }
    buffer.write(text.substring(cursor));

    return RedactionResult(
      text: buffer.toString(),
      matches: List.unmodifiable(accepted),
      // Snapshot: for a session this is the *cumulative* vault, so the result
      // can restore replies that reference tokens from earlier turns.
      mapping: Map.unmodifiable(Map.of(vault)),
    );
  }

  /// Convenience wrapper returning only the redacted text.
  String scrub(String text) => redact(text).text;

  /// Seeds [counters] past any token-shaped literals already present in the
  /// input, so generated placeholders never collide with pre-existing text
  /// (and restore can never corrupt the user's own literal `[EMAIL_1]`).
  static void _seedCounters(String text, Map<String, int> counters) {
    for (final m in _literalToken.allMatches(text)) {
      final label = m.group(1)!;
      final index = int.parse(m.group(2)!);
      if (index > (counters[label] ?? 0)) counters[label] = index;
    }
  }

  static final RegExp _literalToken = RegExp(r'\[([A-Z][A-Z0-9_]*)_(\d+)\]');

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

/// A stateful redaction scope that keeps tokens consistent across calls —
/// what a multi-turn LLM conversation needs.
///
/// Each plain [Redactor.redact] call restarts indices at 1, so in a chat,
/// turn one's `[EMAIL_1]` (alice) and turn two's `[EMAIL_1]` (bob) would be
/// two *different* values behind one token: the model sees an ambiguous
/// conversation, and restoring a reply that references an earlier turn
/// substitutes the wrong data. A session keeps one vault for its whole
/// lifetime: the same value maps to the same token forever, new values keep
/// counting up, and [restore] works for a reply referencing any turn.
///
/// ```dart
/// final session = RedactionSession();
/// session.redact('mail alice@x.com').text; // mail [EMAIL_1]
/// session.redact('mail bob@x.com').text;   // mail [EMAIL_2]
/// session.restore('cc [EMAIL_1] and [EMAIL_2]');
/// // -> 'cc alice@x.com and bob@x.com'
/// ```
///
/// Use [toJson]/[RedactionSession.fromJson] to persist a session across app
/// restarts. **The serialized vault contains the original PII by design** —
/// store it only somewhere as protected as the source data itself.
class RedactionSession {
  /// Creates an empty session. [redactor] defaults to `Redactor()`.
  RedactionSession({Redactor? redactor}) : redactor = redactor ?? Redactor();

  /// Restores a session persisted with [toJson].
  ///
  /// The [redactor] configuration is not serialized; pass the same one the
  /// session was created with.
  factory RedactionSession.fromJson(
    Map<String, Object?> json, {
    Redactor? redactor,
  }) {
    final session = RedactionSession(redactor: redactor);
    (json['counters'] as Map<Object?, Object?>? ?? {}).forEach(
      (label, index) => session._counters[label! as String] = index! as int,
    );
    (json['indices'] as Map<Object?, Object?>? ?? {}).forEach((label, values) {
      final perValue = session._indices.putIfAbsent(label! as String, () => {});
      (values! as Map<Object?, Object?>).forEach(
        (value, index) => perValue[value! as String] = index! as int,
      );
    });
    (json['vault'] as Map<Object?, Object?>? ?? {}).forEach(
      (token, value) => session._vault[token! as String] = value! as String,
    );
    return session;
  }

  /// The redactor whose detectors and styles this session applies.
  final Redactor redactor;

  final Map<String, Map<String, int>> _indices = {};
  final Map<String, int> _counters = {};
  final Map<String, String> _vault = {};

  /// Redacts [text], keeping tokens consistent with every earlier call: a
  /// value seen before reuses its token, and the returned
  /// [RedactionResult.mapping] is the cumulative session vault.
  RedactionResult redact(String text) => redactor._redact(
        text,
        indices: _indices,
        counters: _counters,
        vault: _vault,
      );

  /// Convenience wrapper returning only the redacted text.
  String scrub(String text) => redact(text).text;

  /// Substitutes original values into [input] for tokens from *any* turn of
  /// this session, with the same lenient matching as [restoreTokens].
  String restore(String input) => restoreTokens(input, _vault);

  /// A read-only snapshot of the accumulated token → original-value vault.
  Map<String, String> get vault => Map.unmodifiable(_vault);

  /// Serializes the session state (counters, value indices, and the vault).
  ///
  /// The output contains the original PII — treat it like the data itself.
  Map<String, Object?> toJson() => {
        'version': 1,
        'counters': Map<String, Object?>.of(_counters),
        'indices': {
          for (final entry in _indices.entries)
            entry.key: Map<String, Object?>.of(entry.value),
        },
        'vault': Map<String, Object?>.of(_vault),
      };
}
