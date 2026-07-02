import 'package:redact/redact.dart';
import 'package:test/test.dart';

void main() {
  group('PiiType', () {
    test('every value has a stable uppercase label', () {
      for (final type in PiiType.values) {
        expect(type.label, matches(RegExp(r'^[A-Z0-9_]+$')),
            reason: '${type.name} label should be uppercase/underscore/digit');
      }
    });

    test('labels are unique across types (except custom aliasing PII)', () {
      final labels = PiiType.values.map((t) => t.label).toList();
      expect(labels.toSet().length, labels.length);
    });
  });

  group('PiiMatch', () {
    test('value equals the spanned substring', () {
      const text = 'contact jane@example.com now';
      const match = PiiMatch(
        type: PiiType.email,
        value: 'jane@example.com',
        start: 8,
        end: 24,
      );
      expect(text.substring(match.start, match.end), match.value);
      expect(match.length, match.value.length);
    });

    test('token uses the type label, or the custom label for custom', () {
      expect(
        const PiiMatch(type: PiiType.email, value: 'a@b.co', start: 0, end: 6)
            .token,
        'EMAIL',
      );
      expect(
        const PiiMatch(
          type: PiiType.custom,
          value: 'MRN-42',
          start: 0,
          end: 6,
          label: 'PATIENT_ID',
        ).token,
        'PATIENT_ID',
      );
    });

    test('overlaps detects intersecting spans only', () {
      const a = PiiMatch(type: PiiType.ssn, value: 'x', start: 0, end: 10);
      const b = PiiMatch(type: PiiType.ssn, value: 'y', start: 5, end: 15);
      const c = PiiMatch(type: PiiType.ssn, value: 'z', start: 10, end: 20);
      expect(a.overlaps(b), isTrue);
      expect(b.overlaps(a), isTrue);
      expect(a.overlaps(c), isFalse, reason: 'adjacent spans do not overlap');
    });

    test('sorts by start, then longer span first', () {
      const early = PiiMatch(type: PiiType.email, value: 'e', start: 2, end: 5);
      const longer =
          PiiMatch(type: PiiType.phone, value: 'p', start: 10, end: 20);
      const shorter =
          PiiMatch(type: PiiType.ssn, value: 's', start: 10, end: 15);
      final sorted = [shorter, longer, early]..sort();
      expect(sorted, [early, longer, shorter]);
    });

    test('value equality and hashCode', () {
      const a = PiiMatch(type: PiiType.email, value: 'a@b.co', start: 0, end: 6);
      const b = PiiMatch(type: PiiType.email, value: 'a@b.co', start: 0, end: 6);
      expect(a, b);
      expect(a.hashCode, b.hashCode);
    });

    test('rejects an empty or inverted span', () {
      expect(
        () => PiiMatch(type: PiiType.email, value: '', start: 5, end: 5),
        throwsA(isA<AssertionError>()),
      );
    });
  });
}
