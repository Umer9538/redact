import 'package:redact/redact.dart';
import 'package:test/test.dart';

PiiMatch _m(PiiType type, String value) =>
    PiiMatch(type: type, value: value, start: 0, end: value.length);

void main() {
  group('RedactionStyle.replacement', () {
    final email = _m(PiiType.email, 'jane@acme.com');

    test('placeholder is an indexed, reversible token', () {
      expect(RedactionStyle.placeholder.replacement(email, 1), '[EMAIL_1]');
      expect(RedactionStyle.placeholder.replacement(email, 3), '[EMAIL_3]');
      expect(RedactionStyle.placeholder.isReversible, isTrue);
    });

    test('label drops the index', () {
      expect(RedactionStyle.label.replacement(email, 2), '[EMAIL]');
      expect(RedactionStyle.label.isReversible, isFalse);
    });

    test('remove yields an empty string', () {
      expect(RedactionStyle.remove.replacement(email, 1), isEmpty);
    });

    test('custom label flows into the token for custom matches', () {
      const custom = PiiMatch(
        type: PiiType.custom,
        value: 'MRN-9',
        start: 0,
        end: 5,
        label: 'PATIENT_ID',
      );
      expect(
        RedactionStyle.placeholder.replacement(custom, 1),
        '[PATIENT_ID_1]',
      );
    });
  });

  group('mask (type-aware partial reveal)', () {
    test('card keeps the last four digits and separators', () {
      expect(
        maskValue(_m(PiiType.creditCard, '4111 1111 1111 1111')),
        '•••• •••• •••• 1111',
      );
    });

    test('phone keeps the last two digits', () {
      expect(maskValue(_m(PiiType.phone, '415-555-0132')), '•••-•••-••32');
    });

    test('email keeps the first character and the domain', () {
      expect(maskValue(_m(PiiType.email, 'jane@acme.com')), 'j•••@acme.com');
    });

    test('other types keep only the first and last character', () {
      expect(maskValue(_m(PiiType.ssn, '123-45-6789')), '1•••••••••9');
    });
  });
}
