import 'package:redact/redact.dart';
import 'package:test/test.dart';

/// The precision-first contract, as a regression corpus: ordinary text that
/// merely *resembles* PII must never be redacted. Every line here was chosen
/// adversarially (dates, versions, hashes, prices, identifiers, code) — if a
/// detector change makes any of them fire, that is a false-positive
/// regression, not a recall win.
const cleanCorpus = <String>[
  // Dates and times in common formats.
  'the invoice is dated 2024-01-15 and due 2024-02-15',
  'geliefert am 12.04.2026 um 14 Uhr',
  'meeting moved from 12:30 to 14:45:30 today',
  'Q3 spans 2019-2024 in the old reporting scheme',
  'timestamp 2026-07-02T14:30:00 in the logs',
  // Versions, builds, and hashes.
  'upgrade from v1.2.3 to 2.0.0-rc.1 tonight',
  'Python 3.12.4 and Dart 3.11.5 are installed',
  'commit deadbeefcafe4567890abcdef123456789abcdef0 broke CI',
  'md5 9e107d9d372bb6826bd81d3542a419d6 matches',
  'uuid 550e8400-e29b-41d4-a716-446655440000 assigned',
  'build #1234 finished in 92 seconds',
  // Money, quantities, scores, references.
  r'total $1,234.56 plus Rs 5,000 shipping',
  'the score was 3-2 after extra time',
  'see pages 12-34 and section 4.2.1',
  'ISBN 978-0-306-40615-7 is out of print',
  'order 1234567890123456 shipped yesterday',
  'ref 1234-5678 closed as duplicate',
  'lot 12345-123-1 passed inspection',
  // Identifiers, code, and paths.
  'hex color #FF5733 with opacity 0.8',
  'aspect ratio 16:9 on the new display',
  'John 3:16 is often quoted',
  'run flutter pub get in /home/user/app-2.0',
  'the secret is safe with me, I promise',
  'call sk-request-handler-factory-impl before dispose',
  'assets logo@2x.png and icon@3x.jpg updated',
  'flight PK-301 departs at gate A7',
  'room 12-34 on floor 3',
  'CNIC verification is required by the bank', // word only, no number
  'a.b.c is not a token and neither is x.y.z',
  'ping @channel about the deploy',
  'markdown table | col 1 | col 2 | renders fine',
];

/// One canonical positive per category — the recall floor. If a detector
/// change makes any of these stop firing, a documented capability broke.
const positives = <String, String>{
  'jane.doe@acme.com': 'EMAIL',
  '+923001234567': 'PHONE',
  '415-555-0132': 'PHONE',
  '4111 1111 1111 1111': 'CREDIT_CARD',
  '123-45-6789': 'SSN',
  '912-70-1234': 'ITIN',
  'PK36 SCBL 0000 0011 2345 6702': 'IBAN',
  '192.168.0.1': 'IPV4',
  '2001:db8::8a2e:370:7334': 'IPV6',
  '01:23:45:67:89:ab': 'MAC',
  'AKIAIOSFODNN7EXAMPLE': 'SECRET',
};

void main() {
  group('false-positive trap corpus', () {
    final redactor = Redactor();
    for (final line in cleanCorpus) {
      test('stays clean: "$line"', () {
        final result = redactor.redact(line);
        expect(result.hasPii, isFalse,
            reason: 'false positives: ${result.matches}');
        expect(result.text, line);
      });
    }
  });

  group('recall floor', () {
    final redactor = Redactor();
    positives.forEach((value, label) {
      test('still catches $label: "$value"', () {
        final result = redactor.redact('please use $value thanks');
        expect(result.text, 'please use [${label}_1] thanks');
        expect(result.restore(result.text), 'please use $value thanks');
      });
    });
  });
}
