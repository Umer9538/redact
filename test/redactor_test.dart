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

    test('restore tolerates LLM token mangling', () {
      final result = Redactor().redact('mail jane@acme.com');
      // Markdown-escaped underscore, lowercased, and both at once.
      expect(result.restore(r'sent to [EMAIL\_1].'), 'sent to jane@acme.com.');
      expect(result.restore('sent to [email_1].'), 'sent to jane@acme.com.');
      expect(result.restore(r'sent to [email\_1].'), 'sent to jane@acme.com.');
      // Bold-wrapped tokens work because the brackets survive.
      expect(
        result.restore('sent to **[EMAIL_1]**.'),
        'sent to **jane@acme.com**.',
      );
    });

    test('restore never clobbers [X_1] inside [X_10]', () {
      final emails = List.generate(10, (i) => 'user$i@x.com');
      final result = Redactor().redact(emails.join(' '));
      expect(result.text, contains('[EMAIL_10]'));
      expect(result.restore(result.text), emails.join(' '));
    });

    test('a literal token already in the input is left alone', () {
      // The input itself contains '[EMAIL_1]'; the real email must be seeded
      // past it, and restore must not touch the user's literal text.
      const original = 'template uses [EMAIL_1]; contact jane@acme.com';
      final result = Redactor().redact(original);
      expect(result.text, 'template uses [EMAIL_1]; contact [EMAIL_2]');
      expect(result.mapping.keys, ['[EMAIL_2]']);
      expect(result.restore(result.text), original);
    });

    test('restoreTokens is single-pass: restored values are not rescanned', () {
      final out = restoreTokens(
        'a [X_1] b',
        {'[X_1]': 'contains [Y_1]', '[Y_1]': 'MUST NOT APPEAR'},
      );
      expect(out, 'a contains [Y_1] b');
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

    test('a full IBAN beats a Luhn-valid card matched inside it', () {
      // AT61's digit run is Luhn-valid, so the card detector claims a
      // fragment; the longer mod-97-validated IBAN span must win, leaving no
      // 'AT61 ' prefix in cleartext.
      final result = Redactor().redact('pay AT61 1904 3002 3457 3201, thanks');
      expect(result.text, 'pay [IBAN_1], thanks');
      expect(result.matches.single.type, PiiType.iban);
    });

    test('a card followed by its expiry is redacted, not blackholed', () {
      final result = Redactor().redact('pay 4111 1111 1111 1111 12/26 now');
      expect(result.text, 'pay [CREDIT_CARD_1] 12/26 now');
      expect(result.matches.single.type, PiiType.creditCard);
    });

    test('an SSN adjacent to a phone number yields two clean matches', () {
      // The phone pattern can bridge both into one 15-digit span; the mixed
      // separator rule must reject the bridge so each is caught separately.
      final result = Redactor().redact('id 123-45-6789 415-555-0132 end');
      expect(result.text, 'id [SSN_1] [PHONE_1] end');
    });

    test('a card adjacent to an SSN yields two clean matches', () {
      final result =
          Redactor().redact('use 4111 1111 1111 1111 123-45-6789 end');
      expect(result.text, 'use [CREDIT_CARD_1] [SSN_1] end');
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

  group('detect', () {
    test('returns the exact spans redact would rewrite, without rewriting', () {
      const text = 'mail a@b.com or call 415-555-0132';
      final redactor = Redactor();
      final spans = redactor.detect(text);
      expect(spans, redactor.redact(text).matches);
      for (final m in spans) {
        expect(text.substring(m.start, m.end), m.value);
      }
    });

    test('spans are sorted and non-overlapping', () {
      final spans = Redactor().detect('a@b.com 4111 1111 1111 1111 ::1');
      for (var i = 1; i < spans.length; i++) {
        expect(spans[i].start, greaterThanOrEqualTo(spans[i - 1].end));
      }
    });
  });

  group('allowList', () {
    test('allow-listed values are never redacted', () {
      final redactor = Redactor(allowList: {'support@acme.com'});
      final result =
          redactor.redact('write support@acme.com, not jane@acme.com');
      expect(result.text, 'write support@acme.com, not [EMAIL_1]');
      expect(result.mapping['[EMAIL_1]'], 'jane@acme.com');
    });
  });

  group('KeywordDetector', () {
    test('redacts known literals with the given label', () {
      final redactor = Redactor(detectors: [
        KeywordDetector(
            keywords: ['Jane Austen', 'Project Nightjar'], label: 'NAME'),
        ...Detectors.defaults,
      ]);
      final result = redactor
          .redact('Jane Austen shared Project Nightjar with jane@acme.com');
      expect(result.text, '[NAME_1] shared [NAME_2] with [EMAIL_1]');
      expect(result.restore(result.text),
          'Jane Austen shared Project Nightjar with jane@acme.com');
    });

    test('is case-insensitive by default and word-bounded', () {
      final detector = KeywordDetector(keywords: ['umer']);
      expect(detector.detect('UMER and Umer').length, 2);
      expect(detector.detect('umerville numeric'), isEmpty);
    });

    test('longer keywords win over their own prefixes', () {
      final detector = KeywordDetector(keywords: ['Jane', 'Jane Austen']);
      final values = detector.detect('by Jane Austen').map((m) => m.value);
      expect(values, ['Jane Austen']);
    });

    test('empty keyword list detects nothing', () {
      expect(KeywordDetector(keywords: const []).detect('anything'), isEmpty);
    });
  });
}
