import 'package:redact/redact.dart';
import 'package:test/test.dart';

void main() {
  group('DetectorPacks.pk', () {
    final redactor = Redactor(
      detectors: [...DetectorPacks.pk, ...Detectors.defaults],
    );

    test('redacts CNIC numbers with a country-prefixed label', () {
      final result = redactor.redact('CNIC 35202-1234567-1 verified');
      expect(result.text, 'CNIC [PK_CNIC_1] verified');
      expect(result.restore(result.text), 'CNIC 35202-1234567-1 verified');
    });

    test('is opt-in: the defaults alone do not catch a CNIC', () {
      expect(Redactor().redact('CNIC 35202-1234567-1').hasPii, isFalse);
    });

    test('does not fire on other dashed digit shapes', () {
      expect(redactor.redact('order 12345-123-1 shipped').hasPii, isFalse);
      expect(redactor.redact('ref 123456-1234567-1 x').hasPii, isFalse);
    });
  });
}
