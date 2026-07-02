import 'package:redact/src/luhn.dart';
import 'package:test/test.dart';

void main() {
  group('isLuhnValid', () {
    test('accepts well-known valid card numbers', () {
      expect(isLuhnValid('4111111111111111'), isTrue); // Visa test number
      expect(isLuhnValid('5500005555555559'), isTrue); // Mastercard test
      expect(isLuhnValid('340000000000009'), isTrue); // Amex test
      expect(isLuhnValid('79927398713'), isTrue); // classic Luhn example
    });

    test('ignores separators (spaces and dashes)', () {
      expect(isLuhnValid('4111 1111 1111 1111'), isTrue);
      expect(isLuhnValid('4111-1111-1111-1111'), isTrue);
    });

    test('rejects numbers that fail the checksum', () {
      expect(isLuhnValid('4111111111111112'), isFalse);
      expect(isLuhnValid('1234567890123456'), isFalse);
      expect(isLuhnValid('79927398710'), isFalse);
    });

    test('rejects input with fewer than two digits', () {
      expect(isLuhnValid(''), isFalse);
      expect(isLuhnValid('0'), isFalse);
      expect(isLuhnValid('   '), isFalse);
    });

    test('a run of zeros is a valid checksum but needs two digits', () {
      expect(isLuhnValid('00'), isTrue);
      expect(isLuhnValid('0000'), isTrue);
    });
  });
}
