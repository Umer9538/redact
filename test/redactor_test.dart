import 'package:redact/redact.dart';
import 'package:test/test.dart';

void main() {
  group('Redactor.redact (defaults)', () {
    final redactor = Redactor();

    test('replaces PII with stable, indexed placeholders', () {
      final result = redactor.redact(
        'Email jane@acme.com or call +1 415-555-0132',
      );
      expect(result.text, 'Email [EMAIL_1] or call [PHONE_1]');
      expect(result.count, 2);
      expect(result.types, {PiiType.email, PiiType.phone});
    });

    test('the same value reuses one placeholder; distinct values increment',
        () {
      final result = redactor.redact(
        'from a@x.com to b@x.com and cc a@x.com',
      );
      expect(result.text, 'from [EMAIL_1] to [EMAIL_2] and cc [EMAIL_1]');
      expect(result.mapping['[EMAIL_1]'], 'a@x.com');
      expect(result.mapping['[EMAIL_2]'], 'b@x.com');
    });

    test('leaves text with no PII untouched', () {
      final result = redactor.redact('the quick brown fox');
      expect(result.text, 'the quick brown fox');
      expect(result.hasPii, isFalse);
      expect(result.mapping, isEmpty);
    });

    test('handles empty input', () {
      final result = redactor.redact('');
      expect(result.text, isEmpty);
      expect(result.hasPii, isFalse);
    });
  });

  group('reversible pipeline', () {
    test('restore rehydrates the model reply', () {
      final redactor = Redactor();
      final result = redactor.redact('Contact jane@acme.com about card '
          '4111 1111 1111 1111');
      // Model only ever saw placeholders:
      expect(result.text, contains('[EMAIL_1]'));
      expect(result.text, contains('[CREDIT_CARD_1]'));
      expect(result.text, isNot(contains('jane@acme.com')));

      final reply = result.restore(
        'I emailed [EMAIL_1] about the card ending [CREDIT_CARD_1].',
      );
      expect(reply, contains('jane@acme.com'));
      expect(reply, contains('4111 1111 1111 1111'));
    });

    test('round-trips: restoring the redacted text returns the original', () {
      final redactor = Redactor();
      const original = 'ssn 123-45-6789, ip 192.168.0.1, mail x@y.io';
      final result = redactor.redact(original);
      expect(result.restore(result.text), original);
    });

    test('non-reversible styles do not populate the vault', () {
      final redactor = Redactor(style: RedactionStyle.label);
      final result = redactor.redact('mail a@b.com');
      expect(result.text, 'mail [EMAIL]');
      expect(result.mapping, isEmpty);
      expect(result.restore(result.text), result.text);
    });
  });

  group('overlap resolution', () {
    test('a more specific detector wins over the generic phone matcher', () {
      // 123-45-6789 is structurally phone-like but is a valid SSN; the spans
      // are identical, so the tie goes to SSN (earlier in Detectors.defaults).
      final result = Redactor().redact('id 123-45-6789 end');
      expect(result.count, 1);
      expect(result.matches.single.type, PiiType.ssn);
      expect(result.text, 'id [SSN_1] end');
    });

    test('a longer span beats a shorter higher-priority match inside it', () {
      // Mirrors the real IBAN-vs-card case: a low-priority detector matching
      // the full value must beat a high-priority detector matching a fragment.
      final fragment = PatternDetector(
        name: 'fragment',
        type: PiiType.custom,
        pattern: RegExp(r'\d{4}'),
        label: 'FRAGMENT',
      );
      final whole = PatternDetector(
        name: 'whole',
        type: PiiType.custom,
        pattern: RegExp(r'AB\d{4}X'),
        label: 'WHOLE',
      );
      final result =
          Redactor(detectors: [fragment, whole]).redact('ref AB1234X done');
      expect(result.matches.single.value, 'AB1234X');
      expect(result.text, 'ref [WHOLE_1] done');
    });
  });

  group('styles', () {
    test('per-category override masks cards but placeholders emails', () {
      final redactor = Redactor(
        styleOverrides: {PiiType.creditCard: RedactionStyle.mask},
      );
      final result = redactor.redact('pay 4111 1111 1111 1111 for a@b.com');
      expect(result.text, 'pay •••• •••• •••• 1111 for [EMAIL_1]');
      // Only the reversible email is in the vault.
      expect(result.mapping.keys, ['[EMAIL_1]']);
    });

    test('custom replacer overrides styles and is treated as reversible', () {
      final redactor = Redactor(
        replacer: (m, i) => '<<${m.token}#$i>>',
      );
      final result = redactor.redact('mail a@b.com');
      expect(result.text, 'mail <<EMAIL#1>>');
      expect(result.restore('done <<EMAIL#1>>'), 'done a@b.com');
    });

    test('scrub returns only the redacted text', () {
      expect(Redactor().scrub('mail a@b.com'), 'mail [EMAIL_1]');
    });
  });
}
