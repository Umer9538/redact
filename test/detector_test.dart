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
      // Only keep runs of digits that sum to an even value. The leading
      // boundary assertion mirrors how real detectors prevent mid-token
      // rescans from matching inside a rejected number.
      final detector = PatternDetector(
        name: 'even-sum',
        type: PiiType.custom,
        pattern: RegExp(r'(?<!\d)\d+'),
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

    test('a rejected candidate does not blackhole later candidates', () {
      // The greedy pattern bridges the space, producing one big span 'aaa aa'
      // that the validator rejects. Scanning must resume inside that span so
      // the valid 'aa' after it is still found (the old behavior resumed at
      // the rejected span's END and silently dropped it).
      final detector = PatternDetector(
        name: 'aa',
        type: PiiType.custom,
        pattern: RegExp(r'(?<![a-z])a[ a]*a(?![a-z])'),
        validator: (v) => v == 'aa',
      );
      final matches = detector.detect('x aaa aa x').toList();
      expect(matches.map((m) => m.value), ['aa']);
    });

    test('refine trims a greedy match to its valid prefix', () {
      final detector = PatternDetector(
        name: 'evens',
        type: PiiType.custom,
        pattern: RegExp(r'(?<!\d)\d+(?!\d)'),
        // Trim trailing digits until the value has even length.
        refine: (raw) {
          var v = raw;
          while (v.isNotEmpty && v.length.isOdd) {
            v = v.substring(0, v.length - 1);
          }
          return v.isEmpty ? null : v;
        },
      );
      const text = 'id 12345 ok';
      final matches = detector.detect(text).toList();
      expect(matches, hasLength(1));
      expect(matches.single.value, '1234');
      // The emitted span must agree with the trimmed value.
      expect(
        text.substring(matches.single.start, matches.single.end),
        '1234',
      );
    });

    test('refine returning null rejects the candidate', () {
      final detector = PatternDetector(
        name: 'never',
        type: PiiType.custom,
        pattern: RegExp(r'\d+'),
        refine: (_) => null,
      );
      expect(detector.detect('123 456'), isEmpty);
    });
  });
}
