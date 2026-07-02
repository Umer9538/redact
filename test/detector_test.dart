import 'package:redact/redact.dart';
import 'package:test/test.dart';

void main() {
  group('PatternDetector', () {
    test('emits a match per hit with exact offsets', () {
      final detector = PatternDetector(
        name: 'digits',
        type: PiiType.custom,
        pattern: RegExp(r'\d+'),
        label: 'NUMBER',
      );
      const text = 'a12b345';
      final matches = detector.detect(text).toList();

      expect(matches.map((m) => m.value), ['12', '345']);
      for (final m in matches) {
        expect(text.substring(m.start, m.end), m.value);
        expect(m.detector, 'digits');
        expect(m.token, 'NUMBER');
      }
    });

    test('validator rejects syntactic-but-invalid matches', () {
      // Only keep runs of digits that sum to an even value.
      final detector = PatternDetector(
        name: 'even-sum',
        type: PiiType.custom,
        pattern: RegExp(r'\d+'),
        validator: (v) =>
            v.codeUnits.map((c) => c - 0x30).reduce((a, b) => a + b).isEven,
      );
      final matches = detector.detect('11 and 12').toList();
      expect(matches.map((m) => m.value), ['11']); // 1+1=2 even; 1+2=3 odd
    });

    test('lookaround context is required but not part of the value', () {
      final detector = PatternDetector(
        name: 'after-id',
        type: PiiType.custom,
        pattern: RegExp(r'(?<=id=)\w+'),
      );
      final matches = detector.detect('id=abc name=xyz').toList();
      expect(matches, hasLength(1));
      expect(matches.single.value, 'abc');
    });

    test('no matches yields an empty iterable', () {
      final detector = PatternDetector(
        name: 'digits',
        type: PiiType.custom,
        pattern: RegExp(r'\d+'),
      );
      expect(detector.detect('no numbers here'), isEmpty);
    });
  });
}
