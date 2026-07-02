import 'detector.dart';
import 'luhn.dart';
import 'pii_type.dart';

/// The built-in [Detector]s and the default detector set.
///
/// Each detector is precision-first: it favours a low false-positive rate over
/// total recall. Where a pattern alone is ambiguous, a semantic validator backs
/// it up — card numbers must pass the Luhn checksum, IBANs the ISO&nbsp;7064
/// mod-97 check, SSNs the SSA allocation rules, and IPv4 octets the 0–255 range.
/// Detectors whose greedy pattern can over-run into adjacent text (cards,
/// IBANs, phones) additionally *refine* the raw match, trimming trailing
/// chunks until the checksum passes instead of discarding the whole span.
abstract final class Detectors {
  /// Email addresses, e.g. `jane.doe@example.com`. Scaled-asset filenames that
  /// merely look like addresses (`logo@2x.png`) are rejected.
  static final Detector email = PatternDetector(
    name: 'email',
    type: PiiType.email,
    pattern: RegExp(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    validator: _plausibleEmail,
  );

  /// Telephone numbers: bare E.164 (`+923001234567`) or numbers with
  /// separators between digit groups, 7–15 digits overall. Date shapes
  /// (`2024-01-15`, `12.04.2026`) and `dddd-dddd` year ranges are rejected,
  /// and a match that bridges into an adjacent number is trimmed back.
  static final Detector phone = PatternDetector(
    name: 'phone',
    type: PiiType.phone,
    pattern: RegExp(
      r'(?<![\w+.-])(?:'
      r'\+\d{7,15}'
      r'|(?:\+\d{1,3}[ .-]|\(\d{1,4}\)[ .-]?)\d{5,13}'
      r'|(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?'
      r'\d{2,4}(?:[ .-]\d{2,8}){1,4}'
      r')(?!\w)',
    ),
    refine: _refinePhone,
    validator: _validPhone,
  );

  /// Payment card numbers: 13–19 digits, contiguous or grouped by a single
  /// consistent separator, that pass the Luhn checksum. A match that bridges
  /// into an adjacent number (an expiry date, say) is trimmed back to the
  /// valid card instead of leaking.
  static final Detector creditCard = PatternDetector(
    name: 'credit-card',
    type: PiiType.creditCard,
    // (?<!\w) only: a '-' before the number ('ref-4111...') must not hide it.
    pattern: RegExp(r'(?<!\w)\d(?:[ -]?\d){12,}(?!\w)'),
    refine: _refineCard,
  );

  /// US Social Security Numbers written `123-45-6789` (dash or space grouped),
  /// excluding SSA-invalid ranges (area 000/666/900+, group 00, serial 0000).
  ///
  /// Note: an SSN-shaped string that fails SSA validation may still be caught
  /// by the more generic [phone] detector — mislabelled, but safely redacted.
  static final Detector ssn = PatternDetector(
    name: 'ssn',
    type: PiiType.ssn,
    pattern: RegExp(r'(?<![\w-])\d{3}[- ]\d{2}[- ]\d{4}(?![\w-])'),
    validator: _validSsn,
  );

  /// US Individual Taxpayer Identification Numbers: SSN-shaped, area `9xx`,
  /// with an IRS-assigned group range.
  static final Detector itin = PatternDetector(
    name: 'itin',
    type: PiiType.itin,
    pattern: RegExp(r'(?<![\w-])9\d{2}[- ]\d{2}[- ]\d{4}(?![\w-])'),
    validator: _validItin,
  );

  /// IMEI device identifiers: 15 digits passing the Luhn checksum, anchored to
  /// an `IMEI` context word so bare 15-digit numbers are not claimed.
  static final Detector imei = PatternDetector(
    name: 'imei',
    type: PiiType.imei,
    pattern: RegExp(
      r'(?<=\bimei\b[:#= ]{0,3})\d{15}(?!\d)',
      caseSensitive: false,
    ),
    validator: isLuhnValid,
  );

  /// IBAN bank account numbers that pass the mod-97 check. When the spaced
  /// form over-runs into a following short word, trailing groups are trimmed
  /// until the checksum passes.
  static final Detector iban = PatternDetector(
    name: 'iban',
    type: PiiType.iban,
    pattern: RegExp(
      r'(?<![A-Za-z0-9])[A-Z]{2}\d{2}'
      r'(?:[A-Za-z0-9]{11,30}|(?: [A-Za-z0-9]{4})+(?: [A-Za-z0-9]{1,4})?)'
      r'(?![A-Za-z0-9])',
    ),
    refine: _refineIban,
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

  /// IPv6 addresses, including `::`-compressed and IPv4-mapped/-embedded
  /// forms such as `::ffff:192.0.2.1`. A match must contain a digit: bare
  /// `::` and letter-only fragments like `ad::be` are prose/code, not
  /// addresses worth the false positive.
  static final Detector ipv6 = PatternDetector(
    name: 'ipv6',
    type: PiiType.ipv6,
    pattern: RegExp(_ipv6),
    validator: _containsDigit,
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

  /// PEM-encoded private keys (`-----BEGIN ... PRIVATE KEY-----` blocks),
  /// including RSA, EC, OpenSSH, PGP and encrypted variants.
  static final Detector pemKey = PatternDetector(
    name: 'pem-key',
    type: PiiType.secret,
    pattern: RegExp(
      r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----'
      r'[\s\S]*?'
      r'-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----',
    ),
  );

  /// High-entropy secrets in well-known formats (AWS, Anthropic, GitHub,
  /// GitLab, Google, Slack, Stripe, OpenAI, npm, PyPI, Hugging Face,
  /// DigitalOcean, Twilio, SendGrid, Telegram). Only recognised prefixes are
  /// matched, so ordinary tokens are left alone.
  static final Detector secret = PatternDetector(
    name: 'secret',
    type: PiiType.secret,
    pattern: RegExp(
      r'(?<![\w-])(?:'
      r'sk-ant-[A-Za-z0-9_-]{20,}'
      r'|AKIA[0-9A-Z]{16}'
      r'|gh[posru]_[A-Za-z0-9]{36}'
      r'|github_pat_[A-Za-z0-9_]{22,}'
      r'|glpat-[A-Za-z0-9_-]{20,}'
      r'|AIza[A-Za-z0-9_-]{35}'
      r'|xox[baprs]-[A-Za-z0-9-]{10,72}'
      r'|[sr]k_(?:live|test)_[0-9A-Za-z]{16,}'
      r'|sk-(?:proj-)?(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}'
      r'|npm_[A-Za-z0-9]{36}'
      r'|pypi-[A-Za-z0-9_-]{50,}'
      r'|hf_[A-Za-z0-9]{30,40}'
      r'|dop_v1_[a-f0-9]{64}'
      r'|SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}'
      r'|(?:AC|SK)[a-f0-9]{32}'
      r'|\d{8,10}:AA[A-Za-z0-9_-]{33}'
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

  /// The recommended set for redacting text bound for an LLM. Overlaps are
  /// resolved by span length first, so this order only breaks ties between
  /// equal-length matches (e.g. an ITIN-shaped span beats the generic phone
  /// matcher). Excludes [url].
  static List<Detector> get defaults => [
        pemKey,
        imei,
        iban,
        creditCard,
        itin,
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

// Raw IPv6 pattern kept out of line for readability. The first three branches
// cover IPv4-mapped/-embedded forms (::ffff:192.0.2.1, 2001:db8::192.0.2.33)
// so they are matched whole rather than half-redacted. Boundary assertions
// prevent firing inside tokens such as `foo::bar` or ending mid-IPv4.
const String _ipv6 = r'(?<![\w:])(?:'
    r'(?:[A-Fa-f0-9]{1,4}:){6}(?:\d{1,3}\.){3}\d{1,3}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,5}:(?:[A-Fa-f0-9]{1,4}:){0,4}(?:\d{1,3}\.){3}\d{1,3}'
    r'|::(?:[A-Fa-f0-9]{1,4}:){0,5}(?:\d{1,3}\.){3}\d{1,3}'
    r'|(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,7}:'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}'
    r'|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}'
    r'|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}'
    r'|:(?::[A-Fa-f0-9]{1,4}){1,7}'
    r')(?![\w:])(?!\.\d)';

final RegExp _nonDigits = RegExp(r'\D');

int _digitCount(String value) =>
    value.codeUnits.where((u) => u >= 0x30 && u <= 0x39).length;

bool _containsDigit(String value) =>
    value.codeUnits.any((u) => u >= 0x30 && u <= 0x39);

/// Whether all non-digit characters in [value] are the same single separator.
bool _oneSeparator(String value) {
  int? separator;
  for (final unit in value.codeUnits) {
    if (unit >= 0x30 && unit <= 0x39) continue;
    if (separator == null) {
      separator = unit;
    } else if (separator != unit) {
      return false;
    }
  }
  return true;
}

bool _plausibleEmail(String value) {
  // Scaled-asset filenames (logo@2x.png) look like emails but are not.
  final domain = value.substring(value.indexOf('@') + 1).toLowerCase();
  return !RegExp(r'^\d+(?:\.\d+)?x\.(?:png|jpe?g|gif|webp|svg|heic)$')
      .hasMatch(domain);
}

/// Trims a phone match that bridged into an adjacent number: while the span
/// fails validation (too many digits, mixed separators from crossing into a
/// neighbouring year/ZIP/date, …), drop the last group — preferring to split
/// at a space, the usual boundary between two numbers. Returns the longest
/// valid prefix, or null when no prefix validates (a date, an ISBN, …).
///
/// The raw span is bounded by the pattern (a handful of groups), so this
/// loop is O(1)-ish per candidate.
String? _refinePhone(String raw) {
  var value = raw;
  while (!_validPhone(value)) {
    var cut = value.lastIndexOf(' ');
    if (cut <= 0) cut = value.lastIndexOf(RegExp(r'[.-]'));
    if (cut <= 0) return null;
    value = value.substring(0, cut);
  }
  return value;
}

bool _validPhone(String value) {
  final digits = _digitCount(value);
  if (digits < 7 || digits > 15) return false;
  // A '+' country code or parenthesised area code is strong phone structure.
  if (value.startsWith('+') || value.contains('(')) return true;
  // Without that structure, be strict: a real phone number is written with
  // ONE separator style throughout, and no single-digit groups. This rejects
  // ISBNs (978-0-306-40615-7), European decimal groupings (1 234 567,89 has
  // a lone '1'), and spans that bridged two different numbers ('123-45-6789
  // 415-555-0132' mixes '-' and ' ').
  if (!_oneSeparator(value)) return false;
  final groups = value.split(RegExp(r'[ .-]'));
  if (groups.any((g) => g.length == 1)) return false;
  // Year ranges and dddd-dddd reference numbers are not phone numbers.
  if (groups.length == 2 && groups[0].length == 4 && groups[1].length == 4) {
    return false;
  }
  if (groups.length == 3 && _looksLikeDate(groups)) return false;
  return true;
}

bool _looksLikeDate(List<String> groups) {
  int? year, a, b;
  if (groups[0].length == 4 && groups[1].length <= 2 && groups[2].length <= 2) {
    year = int.parse(groups[0]); // yyyy-mm-dd
    a = int.parse(groups[1]);
    b = int.parse(groups[2]);
  } else if (groups[2].length == 4 &&
      groups[0].length <= 2 &&
      groups[1].length <= 2) {
    year = int.parse(groups[2]); // dd-mm-yyyy or mm-dd-yyyy
    a = int.parse(groups[0]);
    b = int.parse(groups[1]);
  } else {
    return false;
  }
  if (year < 1900 || year > 2100) return false;
  if (a < 1 || b < 1 || a > 31 || b > 31) return false;
  return a <= 12 || b <= 12; // at least one part must be a plausible month
}

/// Trims a card match that bridged into an adjacent number: drop trailing
/// separator-delimited chunks until 13–19 digits with one consistent separator
/// pass the Luhn checksum. Returns null when no such prefix exists.
///
/// Works on index math (no per-iteration string copies), only running the
/// checksum inside the plausible 13–19 digit window, and bails early on
/// digit-heavy spans no card context could produce — so adversarial
/// separator-digit runs stay cheap.
String? _refineCard(String raw) {
  var digits = _digitCount(raw);
  // A card plus an adjacent number never bridges this many digits; longer
  // spans are IDs/tables, not cards.
  if (digits > 48) return null;
  var end = raw.length;
  while (true) {
    if (digits < 13) return null;
    if (digits <= 19) {
      final value = raw.substring(0, end);
      final compact = value.replaceAll(_nonDigits, '');
      if (_oneSeparator(value) &&
          _noSingleDigitChunks(value) &&
          isLuhnValid(compact)) {
        return value;
      }
    }
    final cut = raw.lastIndexOf(_cardSeparator, end - 1);
    if (cut <= 0) return null;
    for (var i = cut; i < end; i++) {
      final unit = raw.codeUnitAt(i);
      if (unit >= 0x30 && unit <= 0x39) digits--;
    }
    end = cut;
  }
}

final RegExp _cardSeparator = RegExp(r'[ -]');

/// No real card grouping contains a lone digit (4-4-4-4, 4-6-5, 4-4-4-4-3…),
/// so single-digit chunks mark a digit table or list, not a card.
bool _noSingleDigitChunks(String value) {
  var run = 0;
  for (final unit in value.codeUnits) {
    if (unit >= 0x30 && unit <= 0x39) {
      run++;
    } else {
      if (run == 1) return false;
      run = 0;
    }
  }
  return run != 1;
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

bool _validItin(String value) {
  // IRS-assigned ITIN group (4th-5th digit) ranges.
  final group = int.parse(value.split(RegExp(r'[- ]'))[1]);
  return (group >= 50 && group <= 65) ||
      (group >= 70 && group <= 88) ||
      (group >= 90 && group <= 92) ||
      (group >= 94 && group <= 99);
}

/// Trims an IBAN match whose spaced form swallowed a following short word:
/// drop trailing space-separated groups until the mod-97 check passes.
/// Bails early on spans far longer than any IBAN (34 chars + spacing).
String? _refineIban(String raw) {
  if (raw.length > 48) return null;
  var value = raw;
  while (true) {
    if (_validIban(value)) return value;
    final cut = value.lastIndexOf(' ');
    if (cut <= 0) return null;
    value = value.substring(0, cut);
  }
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
