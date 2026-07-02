/// The category of a piece of personally identifiable information.
///
/// These are the built-in categories recognised by the bundled detectors. A
/// custom [Detector] may also emit a [PiiType.custom] match with its own
/// [PiiMatch.label] to describe domain-specific data (e.g. a patient id).
enum PiiType {
  /// An email address, e.g. `jane.doe@example.com`.
  email,

  /// A telephone number in international or common national formats.
  phone,

  /// A payment card number (validated with the Luhn checksum).
  creditCard,

  /// A US Social Security Number, e.g. `123-45-6789`.
  ssn,

  /// A US Individual Taxpayer Identification Number (SSN-shaped, area `9xx`).
  itin,

  /// An IMEI mobile-device identifier (15 digits, Luhn-checked).
  imei,

  /// An IBAN bank account number.
  iban,

  /// An IPv4 address, e.g. `192.168.0.1`.
  ipv4,

  /// An IPv6 address.
  ipv6,

  /// A MAC hardware address, e.g. `01:23:45:67:89:ab`.
  macAddress,

  /// A URL. Off by default because it over-matches ordinary text; enable it
  /// explicitly when links themselves are considered sensitive.
  url,

  /// A JSON Web Token (three base64url segments separated by dots).
  jwt,

  /// A high-entropy secret such as an API key or access token.
  secret,

  /// Data flagged by a custom detector that does not fit a built-in category.
  custom;

  /// A short, uppercase, stable label used to build placeholders and masks
  /// (e.g. `EMAIL`, `CREDIT_CARD`). Stable across releases: it is part of the
  /// redacted output that users may assert against.
  String get label => switch (this) {
        PiiType.email => 'EMAIL',
        PiiType.phone => 'PHONE',
        PiiType.creditCard => 'CREDIT_CARD',
        PiiType.ssn => 'SSN',
        PiiType.itin => 'ITIN',
        PiiType.imei => 'IMEI',
        PiiType.iban => 'IBAN',
        PiiType.ipv4 => 'IPV4',
        PiiType.ipv6 => 'IPV6',
        PiiType.macAddress => 'MAC',
        PiiType.url => 'URL',
        PiiType.jwt => 'JWT',
        PiiType.secret => 'SECRET',
        PiiType.custom => 'PII',
      };
}
