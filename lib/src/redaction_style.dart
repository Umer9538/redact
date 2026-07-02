import 'pii_match.dart';
import 'pii_type.dart';

/// Builds the replacement text for a detected [PiiMatch].
///
/// [index] is a 1-based counter assigned by the [Redactor]: the same original
/// value always receives the same index within one redaction, so a custom
/// replacer can produce stable, reversible tokens.
typedef Replacer = String Function(PiiMatch match, int index);

/// How a detected value is rewritten in the output.
enum RedactionStyle {
  /// A stable, indexed token such as `[EMAIL_1]`. The only built-in style that
  /// is safely reversible: each distinct value maps to a unique token, so the
  /// original can be restored into a model's reply.
  placeholder,

  /// A bare type label such as `[EMAIL]`. Irreversible — all values of a type
  /// collapse to the same token.
  label,

  /// A partial reveal that keeps a value recognisable without exposing it, e.g.
  /// `•••• •••• •••• 1111` for a card or `j•••@example.com` for an email.
  /// Irreversible.
  mask,

  /// Deletes the value entirely, leaving an empty string. Irreversible.
  remove;

  /// Whether output in this style can be restored to the original values.
  bool get isReversible => this == RedactionStyle.placeholder;

  /// The replacement text for [match], given its 1-based [index].
  String replacement(PiiMatch match, int index) => switch (this) {
        RedactionStyle.placeholder => '[${match.token}_$index]',
        RedactionStyle.label => '[${match.token}]',
        RedactionStyle.mask => maskValue(match),
        RedactionStyle.remove => '',
      };
}

/// Returns a masked, partially-revealed form of [match]'s value.
///
/// The reveal is type-aware: cards and phones keep their trailing digits,
/// emails keep the first local character and the domain, and everything else
/// keeps only its first and last character.
String maskValue(PiiMatch match) {
  switch (match.type) {
    case PiiType.creditCard:
      return _revealTrailingDigits(match.value, 4);
    case PiiType.phone:
      return _revealTrailingDigits(match.value, 2);
    case PiiType.email:
      return _maskEmail(match.value);
    default:
      return _revealEnds(match.value);
  }
}

bool _isDigit(int codeUnit) => codeUnit >= 0x30 && codeUnit <= 0x39;

/// Masks every digit except the last [keep], preserving separators.
String _revealTrailingDigits(String value, int keep) {
  final totalDigits = value.codeUnits.where(_isDigit).length;
  final buffer = StringBuffer();
  var seen = 0;
  for (final unit in value.codeUnits) {
    if (_isDigit(unit)) {
      seen++;
      buffer.writeCharCode(seen > totalDigits - keep ? unit : 0x2022); // •
    } else {
      buffer.writeCharCode(unit);
    }
  }
  return buffer.toString();
}

String _maskEmail(String value) {
  final at = value.indexOf('@');
  if (at <= 0) return _revealEnds(value);
  final head = value[0];
  final hiddenLocal = '•' * (at - 1 < 1 ? 1 : at - 1);
  return '$head$hiddenLocal${value.substring(at)}';
}

String _revealEnds(String value) {
  if (value.length <= 2) return '•' * value.length;
  return '${value[0]}${'•' * (value.length - 2)}${value[value.length - 1]}';
}
