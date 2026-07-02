import 'detector.dart';
import 'luhn.dart';
import 'pii_type.dart';

/// The built-in [Detector]s and the default detector set.
///
/// Each detector is precision-first: it favours a low false-positive rate over
/// total recall. Where a pattern alone is ambiguous, a semantic validator backs
/// it up — card numbers must pass the Luhn checksum, IBANs the ISO&nbsp;7064
/// mod-97 check, SSNs the SSA allocation rules, and IPv4 octets the 0–255 range.
abstract final class Detectors {
  /// Email addresses, e.g. `jane.doe@example.com`.
  static final Detector email = PatternDetector(
    name: 'email',
    type: PiiType.email,
    pattern: RegExp(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
  );

  /// Telephone numbers that carry phone-like structure (a `+` prefix or
  /// separators between digit groups) and 7–15 digits overall. Bare digit runs
  /// with no structure are intentionally not matched, to avoid catching order
  /// numbers and similar.
  static final Detector phone = PatternDetector(
    name: 'phone',
    type: PiiType.phone,
    pattern: RegExp(
      r'(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?'
      r'\d{2,4}(?:[ .-]\d{2,4}){1,4}(?!\w)',
    ),
    validator: _validPhone,
  );

  /// Payment card numbers (13–19 digits) that pass the Luhn checksum.
  static final Detector creditCard = PatternDetector(
    name: 'credit-card',
    type: PiiType.creditCard,
    pattern: RegExp(r'(?<!\w)\d(?:[ -]?\d){12,18}(?!\w)'),
    validator: _validCard,
  );

  /// US Social Security Numbers written `123-45-6789` (dash or space grouped),
  /// excluding SSA-invalid ranges (area 000/666/900+, group 00, serial 0000).
  static final Detector ssn = PatternDetector(
    name: 'ssn',
    type: PiiType.ssn,
    pattern: RegExp(r'(?<![\w-])\d{3}[- ]\d{2}[- ]\d{4}(?![\w-])'),
    validator: _validSsn,
  );

  /// IBAN bank account numbers that pass the mod-97 check.
  static final Detector iban = PatternDetector(
    name: 'iban',
    type: PiiType.iban,
    pattern: RegExp(
      r'(?<![A-Za-z0-9])[A-Z]{2}\d{2}'
      r'(?:[A-Za-z0-9]{11,30}|(?: [A-Za-z0-9]{4})+(?: [A-Za-z0-9]{1,4})?)'
      r'(?![A-Za-z0-9])',
    ),
    validator: _validIban,
  );

  /// IPv4 addresses with each octet range-checked to 0–255.
  static final Detector ipv4 = PatternDetector(
    name: 'ipv4',
    type: PiiType.ipv4,
    pattern: RegExp(
      r'(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
      r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.])',
    ),
  );

  /// IPv6 addresses, including `::`-compressed forms.
  static final Detector ipv6 = PatternDetector(
    name: 'ipv6',
    type: PiiType.ipv6,
    pattern: RegExp(_ipv6),
  );

  /// MAC hardware addresses, e.g. `01:23:45:67:89:ab` or dash-separated.
  static final Detector macAddress = PatternDetector(
    name: 'mac',
    type: PiiType.macAddress,
    pattern: RegExp(r'(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}'
        r'(?![\w:-])'),
  );

  /// JSON Web Tokens (three base64url segments beginning `eyJ`).
  static final Detector jwt = PatternDetector(
    name: 'jwt',
    type: PiiType.jwt,
    pattern: RegExp(
      r'(?<![\w-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}'
      r'(?![\w-])',
    ),
  );

  /// High-entropy secrets in well-known formats (AWS, GitHub, Google, Slack,
  /// Stripe, OpenAI). Only recognised prefixes are matched, so ordinary tokens
  /// are left alone.
  static final Detector secret = PatternDetector(
    name: 'secret',
    type: PiiType.secret,
    pattern: RegExp(
      r'(?<![\w-])(?:'
      r'AKIA[0-9A-Z]{16}'
      r'|gh[posru]_[A-Za-z0-9]{36}'
      r'|github_pat_[A-Za-z0-9_]{22,}'
      r'|AIza[A-Za-z0-9_-]{35}'
      r'|xox[baprs]-[A-Za-z0-9-]{10,48}'
      r'|[sr]k_(?:live|test)_[0-9A-Za-z]{16,}'
      r'|sk-(?:proj-)?[A-Za-z0-9_-]{20,}'
      r')(?![\w-])',
    ),
  );

  /// HTTP(S) URLs. Off by default because links appear constantly in ordinary
  /// text; enable it explicitly when URLs are themselves sensitive.
  static final Detector url = PatternDetector(
    name: 'url',
    type: PiiType.url,
    pattern: RegExp(r'''(?<!\w)https?://[^\s<>()"']+'''),
  );

  /// The recommended set for redacting text bound for an LLM. Ordered by
  /// specificity so that, on an overlap, the more specific detector wins (for
  /// example a card number beats the generic phone matcher). Excludes [url].
  static List<Detector> get defaults => [
        creditCard,
        iban,
        ssn,
        secret,
        jwt,
        email,
        ipv6,
        ipv4,
        macAddress,
        phone,
      ];

  /// Every built-in detector, including [url].
  static List<Detector> get all => [...defaults, url];
}

// Raw IPv6 pattern (industry-standard alternation) kept out of line for
// readability. Guarded by boundary assertions so it will not fire inside
// tokens such as `foo::bar`.
const String _ipv6 = r'(?<![\w:])(?:'
    r'(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,7}:'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}'
    r'|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}'
    r'|:(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:)'
    r')(?![\w:])';

bool _validPhone(String value) {
  final digits = value.replaceAll(RegExp(r'\D'), '').length;
  return digits >= 7 && digits <= 15;
}

bool _validCard(String value) {
  final digits = value.replaceAll(RegExp(r'\D'), '');
  return digits.length >= 13 && digits.length <= 19 && isLuhnValid(digits);
}

bool _validSsn(String value) {
  final parts = value.split(RegExp(r'[- ]'));
  if (parts.length != 3) return false;
  final area = int.parse(parts[0]);
  if (area == 0 || area == 666 || area >= 900) return false;
  if (parts[1] == '00') return false;
  if (parts[2] == '0000') return false;
  return true;
}

bool _validIban(String value) {
  final compact = value.replaceAll(' ', '').toUpperCase();
  if (compact.length < 15 || compact.length > 34) return false;
  if (!RegExp(r'^[A-Z]{2}\d{2}[A-Z0-9]+$').hasMatch(compact)) return false;

  // ISO 7064 mod-97: move the first four chars to the end, expand letters to
  // two-digit numbers (A=10 … Z=35), and take the whole thing mod 97 == 1.
  final rearranged = compact.substring(4) + compact.substring(0, 4);
  var remainder = 0;
  for (final unit in rearranged.codeUnits) {
    if (unit >= 0x30 && unit <= 0x39) {
      remainder = (remainder * 10 + (unit - 0x30)) % 97;
    } else {
      remainder = (remainder * 100 + (unit - 0x37)) % 97; // 'A'(0x41) -> 10
    }
  }
  return remainder == 1;
}
