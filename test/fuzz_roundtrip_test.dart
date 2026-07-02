import 'dart:math';

import 'package:redact/redact.dart';
import 'package:test/test.dart';

/// Property-based round-trip fuzzing with a fixed seed (deterministic in CI).
///
/// For hundreds of randomly assembled texts mixing real PII, look-alike noise,
/// Unicode, and adjacency, four invariants must hold:
///  1. restore(redact(x).text) == x  (the reversible pipeline never corrupts)
///  2. every planted PII value is absent from the redacted text (no leaks)
///  3. matches are sorted, non-overlapping, and span-accurate
///  4. redacting the redacted text finds nothing new (idempotence)
void main() {
  const piiPool = <String>[
    'jane.doe@acme.com',
    'ops+alerts@sub.example.co.uk',
    '+923001234567',
    '+1 415-555-0132',
    '0300-1234567',
    '4111 1111 1111 1111',
    '5555-5555-5555-4444',
    '378282246310005',
    '123-45-6789',
    '912-70-1234',
    'PK36 SCBL 0000 0011 2345 6702',
    'DE89370400440532013000',
    '192.168.0.1',
    '::ffff:192.0.2.1',
    '2001:db8::8a2e:370:7334',
    '01:23:45:67:89:ab',
    'AKIAIOSFODNN7EXAMPLE',
    'sk-ant-api03-AbCd1234EfGh5678IjKl',
    'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
  ];

  const noisePool = <String>[
    'meeting',
    'tomorrow',
    'v1.2.3',
    '2024-01-15',
    'the',
    'score 3-2',
    r'$49.99',
    'اردو',
    '日本語',
    '🎉',
    'ISBN 978-0-306-40615-7',
    'ok',
    'now',
    '12:30',
    'deploy',
    '#FF5733',
  ];

  test('300 seeded round-trips hold all four invariants', () {
    final random = Random(42); // fixed seed: reproducible failures
    final redactor = Redactor();

    for (var i = 0; i < 300; i++) {
      final pieces = <String>[];
      final planted = <String>[];
      final length = 3 + random.nextInt(10);
      for (var p = 0; p < length; p++) {
        if (random.nextInt(3) == 0) {
          final value = piiPool[random.nextInt(piiPool.length)];
          planted.add(value);
          pieces.add(value);
        } else {
          pieces.add(noisePool[random.nextInt(noisePool.length)]);
        }
      }
      // Vary the joiner to exercise adjacency and multiline handling.
      final joiner = switch (random.nextInt(4)) {
        0 => ' ',
        1 => ', ',
        2 => '\n',
        _ => '  ',
      };
      final original = pieces.join(joiner);
      final result = redactor.redact(original);

      // 1. Round-trip.
      expect(result.restore(result.text), original,
          reason: 'iteration $i failed round-trip for: $original');

      // 2. No planted value survives in the redacted text.
      for (final value in planted) {
        expect(result.text, isNot(contains(value)),
            reason: 'iteration $i leaked "$value" in: ${result.text}');
      }

      // 3. Matches are sorted, non-overlapping, span-accurate.
      for (var m = 0; m < result.matches.length; m++) {
        final match = result.matches[m];
        expect(original.substring(match.start, match.end), match.value);
        if (m > 0) {
          expect(match.start, greaterThanOrEqualTo(result.matches[m - 1].end));
        }
      }

      // 4. Idempotence: nothing new hides in the redacted text.
      final second = redactor.redact(result.text);
      expect(second.hasPii, isFalse,
          reason: 'iteration $i re-detected in: ${result.text} '
              '-> ${second.matches}');
    }
  });
}
