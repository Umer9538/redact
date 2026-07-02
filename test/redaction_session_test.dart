import 'dart:convert';

import 'package:redact/redact.dart';
import 'package:test/test.dart';

void main() {
  group('RedactionSession', () {
    test('distinct values get distinct tokens across turns', () {
      // With per-call Redactor.redact, both turns would produce [EMAIL_1] for
      // two different people — ambiguous to the model and wrong on restore.
      final session = RedactionSession();
      expect(session.redact('mail alice@x.com').text, 'mail [EMAIL_1]');
      expect(session.redact('mail bob@x.com').text, 'mail [EMAIL_2]');
    });

    test('the same value reuses its token across turns', () {
      final session = RedactionSession();
      expect(session.redact('mail alice@x.com').text, 'mail [EMAIL_1]');
      expect(session.redact('remind alice@x.com').text, 'remind [EMAIL_1]');
    });

    test('restore works for a reply referencing any turn', () {
      final session = RedactionSession();
      session.redact('alice@x.com asked about card 4111 1111 1111 1111');
      session.redact('bob@x.com approved it');
      expect(
        session.restore('Tell [EMAIL_2] that [EMAIL_1] used [CREDIT_CARD_1].'),
        'Tell bob@x.com that alice@x.com used 4111 1111 1111 1111.',
      );
    });

    test('each result carries the cumulative vault', () {
      final session = RedactionSession();
      session.redact('mail alice@x.com');
      final second = session.redact('mail bob@x.com');
      expect(second.mapping.keys, containsAll(['[EMAIL_1]', '[EMAIL_2]']));
      expect(
        second.restore('cc [EMAIL_1]'),
        'cc alice@x.com',
        reason: 'a later result must restore earlier turns',
      );
    });

    test('serializes and resumes: indices keep counting after fromJson', () {
      final session = RedactionSession();
      session.redact('mail alice@x.com and bob@x.com');

      final revived = RedactionSession.fromJson(
        jsonDecode(jsonEncode(session.toJson())) as Map<String, Object?>,
      );
      expect(revived.redact('mail carol@x.com').text, 'mail [EMAIL_3]');
      expect(revived.redact('mail alice@x.com').text, 'mail [EMAIL_1]');
      expect(revived.restore('[EMAIL_2]?'), 'bob@x.com?');
    });

    test('literal tokens in a later turn still cannot collide', () {
      final session = RedactionSession();
      session.redact('mail alice@x.com'); // [EMAIL_1]
      final result = session.redact('template [EMAIL_5]; mail bob@x.com');
      expect(result.text, 'template [EMAIL_5]; mail [EMAIL_6]');
    });

    test('vault getter is a read-only snapshot', () {
      final session = RedactionSession();
      session.redact('mail alice@x.com');
      expect(() => session.vault['[X_1]'] = 'nope', throwsUnsupportedError);
    });

    test('uses the configured redactor (styles, allowList)', () {
      final session = RedactionSession(
        redactor: Redactor(allowList: {'support@acme.com'}),
      );
      expect(
        session.redact('cc support@acme.com and jane@acme.com').text,
        'cc support@acme.com and [EMAIL_1]',
      );
    });
  });
}
