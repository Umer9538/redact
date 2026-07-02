import 'package:redact/redact.dart';
import 'package:test/test.dart';

/// Collects the string values a detector finds in [text].
List<String> found(Detector d, String text) =>
    d.detect(text).map((m) => m.value).toList();

void main() {
  group('email', () {
    final d = Detectors.email;
    test('matches common address shapes', () {
      expect(found(d, 'reach jane.doe+tag@sub.example.co.uk please'),
          ['jane.doe+tag@sub.example.co.uk']);
      expect(found(d, 'a@b.io and c_d@e-f.com'), ['a@b.io', 'c_d@e-f.com']);
    });
    test('does not match bare @ handles or domains', () {
      expect(found(d, 'ping @handle on the site example.com'), isEmpty);
    });
    test('does not match scaled-asset filenames', () {
      expect(found(d, 'use logo@2x.png and icon@3x.jpg here'), isEmpty);
      expect(found(d, 'hero@1.5x.webp too'), isEmpty);
    });
  });

  group('phone', () {
    final d = Detectors.phone;
    test('matches structured numbers', () {
      expect(found(d, 'call +1 415-555-0132 now'), ['+1 415-555-0132']);
      expect(found(d, 'tel (020) 7946 0958'), ['(020) 7946 0958']);
      expect(found(d, 'ph 415.555.0199'), ['415.555.0199']);
    });
    test('matches bare E.164 numbers', () {
      expect(found(d, 'wa +14155550132 ok'), ['+14155550132']);
      expect(found(d, 'call +923001234567 today'), ['+923001234567']);
    });
    test('matches numbers with a long final group (PK formats)', () {
      expect(found(d, 'mob +92 300 1234567 pls'), ['+92 300 1234567']);
      expect(found(d, 'mob 0300-1234567 pls'), ['0300-1234567']);
      expect(found(d, 'mob 0301 2345678 pls'), ['0301 2345678']);
    });
    test('two adjacent phone numbers are both caught in full', () {
      expect(
        found(d, 'try 415-555-0132 415-555-0199 later'),
        ['415-555-0132', '415-555-0199'],
      );
    });
    test('a phone before a short digit run is trimmed back, not leaked', () {
      // The bridge into the year/ZIP/date is <=15 digits, so only a
      // validator-driven trim can recover the phone.
      final suffixes = ['24/7', '2024', '94105', '100 times', '12.05.2024'];
      for (final suffix in suffixes) {
        expect(found(d, 'call 415-555-0132 $suffix ok'), ['415-555-0132'],
            reason: 'suffix "$suffix" must not defeat the phone');
      }
      expect(found(d, '415.555.0132 2024'), ['415.555.0132']);
    });
    test('matches strong prefixes with a contiguous national block', () {
      expect(found(d, 'mob +92 3001234567 pls'), ['+92 3001234567']);
      expect(found(d, 'tel (021) 34567890 pls'), ['(021) 34567890']);
      expect(found(d, 'tel +49 30901820 x'), ['+49 30901820']);
    });
    test('matches 8-digit subscriber groups (PK/DE landlines)', () {
      expect(found(d, 'll 021 34567890 pls'), ['021 34567890']);
    });
    test('ignores bare digit runs and too-short/long sequences', () {
      expect(found(d, 'order 1234567890123456 shipped'), isEmpty);
      expect(found(d, 'room 12-34'), isEmpty); // only 4 digits
    });
    test('ignores dates, year ranges, and dddd-dddd references', () {
      expect(found(d, 'shipped 2024-01-15 by air'), isEmpty);
      expect(found(d, 'am 12.04.2026 geliefert'), isEmpty);
      expect(found(d, 'seasons 2019-2024 combined'), isEmpty);
      expect(found(d, 'ref 1234-5678 closed'), isEmpty);
    });
  });

  group('credit card', () {
    final d = Detectors.creditCard;
    test('matches Luhn-valid cards, grouped or contiguous', () {
      expect(found(d, 'card 4111 1111 1111 1111 ok'), ['4111 1111 1111 1111']);
      expect(found(d, 'pan 4111111111111111'), ['4111111111111111']);
    });
    test('rejects Luhn-invalid 16-digit numbers', () {
      expect(found(d, 'ref 4111111111111112'), isEmpty);
      expect(found(d, 'id 1234567812345678'), isEmpty);
    });
    test('a card followed by an adjacent number is trimmed, not leaked', () {
      expect(found(d, 'card 4111 1111 1111 1111 12/26 thx'),
          ['4111 1111 1111 1111']);
      expect(found(d, 'card 4111 1111 1111 1111 12'), ['4111 1111 1111 1111']);
    });
    test('does not bridge two adjacent SSN-shaped numbers into a card', () {
      expect(found(d, 'ssns 123-45-6789 123-45-6789 end'), isEmpty);
    });
    test('rejects mixed-separator groupings', () {
      expect(found(d, 'odd 4111-1111 1111-1111 end'), isEmpty);
    });
    test('rejects long contiguous digit runs outright', () {
      expect(found(d, 'id 41111111111111111111 end'), isEmpty); // 20 digits
    });
    test('a card glued behind a dash is still detected', () {
      expect(found(d, 'ref-4111111111111111 shipped'), ['4111111111111111']);
      expect(found(d, 'nr-4111 1111 1111 1111 ok'), ['4111 1111 1111 1111']);
    });
    test('adversarial separator-digit runs stay fast and clean', () {
      // 10KB of '1 2 3 4 ...' used to trigger a refine blowup measured in
      // tens of seconds; with early bails it must finish quickly and match
      // nothing.
      final adversarial = List.generate(5000, (i) => i % 10).join(' ');
      final stopwatch = Stopwatch()..start();
      final result = Redactor().redact(adversarial);
      stopwatch.stop();
      expect(result.hasPii, isFalse);
      expect(stopwatch.elapsedMilliseconds, lessThan(2000),
          reason: 'took ${stopwatch.elapsedMilliseconds} ms');
    });
  });

  group('ssn', () {
    final d = Detectors.ssn;
    test('matches valid SSNs', () {
      expect(found(d, 'ssn 123-45-6789'), ['123-45-6789']);
      expect(found(d, 'ssn 123 45 6789'), ['123 45 6789']);
    });
    test('rejects SSA-invalid ranges', () {
      expect(found(d, '000-45-6789'), isEmpty);
      expect(found(d, '666-45-6789'), isEmpty);
      expect(found(d, '900-45-6789'), isEmpty);
      expect(found(d, '123-00-6789'), isEmpty);
      expect(found(d, '123-45-0000'), isEmpty);
    });
  });

  group('iban', () {
    final d = Detectors.iban;
    test('matches mod-97-valid IBANs (spaced or contiguous)', () {
      expect(found(d, 'iban GB82 WEST 1234 5698 7654 32 end'),
          ['GB82 WEST 1234 5698 7654 32']);
      expect(found(d, 'DE89370400440532013000'), ['DE89370400440532013000']);
    });
    test('a spaced IBAN followed by a short word is trimmed, not missed', () {
      // The optional trailing group used to swallow the next 1-4 char word,
      // fail mod-97, and silently leak the whole account number.
      const iban = 'PK36 SCBL 0000 0011 2345 6702';
      for (final tail in ['ok', 'now', 'x', '2026', 'ok x']) {
        expect(found(d, 'my iban is $iban $tail'), [iban],
            reason: 'trailing "$tail" must not defeat the match');
      }
    });
    test('rejects check-digit-invalid IBANs', () {
      expect(found(d, 'GB00 WEST 1234 5698 7654 32'), isEmpty);
    });
  });

  group('itin', () {
    final d = Detectors.itin;
    test('matches ITINs in IRS-assigned group ranges', () {
      expect(found(d, 'itin 912-70-1234 filed'), ['912-70-1234']);
      expect(found(d, 'itin 998 88 4321 filed'), ['998 88 4321']);
    });
    test('rejects non-9xx areas and unassigned groups', () {
      expect(found(d, '123-70-1234'), isEmpty); // not 9xx
      expect(found(d, '912-69-1234'), isEmpty); // group 69 unassigned
      expect(found(d, '912-89-1234'), isEmpty); // group 89 unassigned
      expect(found(d, '912-93-1234'), isEmpty); // group 93 unassigned
    });
  });

  group('imei', () {
    final d = Detectors.imei;
    test('matches Luhn-valid IMEIs after a context word', () {
      expect(found(d, 'IMEI: 490154203237518 blocked'), ['490154203237518']);
      expect(found(d, 'imei 490154203237518'), ['490154203237518']);
    });
    test('requires the context word and the checksum', () {
      expect(found(d, 'serial 490154203237518'), isEmpty); // no context
      expect(found(d, 'IMEI: 490154203237519'), isEmpty); // bad Luhn
    });
  });

  group('ipv4', () {
    final d = Detectors.ipv4;
    test('matches valid addresses', () {
      expect(found(d, 'host 192.168.0.1 up'), ['192.168.0.1']);
      expect(found(d, 'dns 8.8.8.8'), ['8.8.8.8']);
    });
    test('rejects out-of-range octets and version strings', () {
      expect(found(d, 'bad 256.1.1.1'), isEmpty);
      expect(found(d, 'v 1.2.3 released'), isEmpty); // only 3 octets
    });
  });

  group('ipv6', () {
    final d = Detectors.ipv6;
    test('matches full and compressed forms', () {
      expect(found(d, 'addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 x'),
          ['2001:0db8:85a3:0000:0000:8a2e:0370:7334']);
      expect(found(d, 'loop ::1 here'), ['::1']);
      expect(found(d, 'short 2001:db8::8a2e:370:7334'),
          ['2001:db8::8a2e:370:7334']);
    });
    test('matches IPv4-mapped and -embedded forms in full', () {
      // These used to half-match ('::ffff:192' + leaked '.0.2.1').
      expect(found(d, 'x ::ffff:192.0.2.1 y'), ['::ffff:192.0.2.1']);
      expect(found(d, 'x ::192.0.2.1 y'), ['::192.0.2.1']);
      expect(found(d, 'x 2001:db8::192.0.2.33 y'), ['2001:db8::192.0.2.33']);
      expect(found(d, 'x 64:ff9b::192.0.2.1 y'), ['64:ff9b::192.0.2.1']);
    });
  });

  group('mac', () {
    final d = Detectors.macAddress;
    test('matches colon and dash forms', () {
      expect(found(d, 'nic 01:23:45:67:89:ab'), ['01:23:45:67:89:ab']);
      expect(found(d, 'nic 01-23-45-67-89-AB'), ['01-23-45-67-89-AB']);
    });
  });

  group('jwt', () {
    final d = Detectors.jwt;
    test('matches three-segment tokens starting eyJ', () {
      const token =
          'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N';
      expect(found(d, 'auth $token end'), [token]);
    });
    test('does not match a plain dotted word', () {
      expect(found(d, 'a.b.c is not a token'), isEmpty);
    });
  });

  group('secret', () {
    final d = Detectors.secret;
    test('matches well-known key formats', () {
      expect(
          found(d, 'key AKIAIOSFODNN7EXAMPLE used'), ['AKIAIOSFODNN7EXAMPLE']);
      expect(
        found(d, 'gh ghp_1234567890abcdefghijklmnopqrstuvwxyz done'),
        ['ghp_1234567890abcdefghijklmnopqrstuvwxyz'],
      );
      expect(found(d, 'stripe sk_live_0123456789abcdefghijkl x'),
          ['sk_live_0123456789abcdefghijkl']);
    });
    test('does not match ordinary words', () {
      expect(found(d, 'the secret is safe with me'), isEmpty);
      // Kebab-case identifiers must not trip the OpenAI sk- prefix.
      expect(found(d, 'use sk-request-handler-factory-impl here'), isEmpty);
    });
    test('matches current-length Slack tokens', () {
      const token = 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx';
      expect(found(d, 'slack $token end'), [token]);
    });
    test('matches the expanded provider prefixes', () {
      final cases = {
        'anthropic': 'sk-ant-api03-AbCd1234EfGh5678IjKl',
        'gitlab': 'glpat-AbCd1234EfGh5678IjKl',
        'npm': 'npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
        'huggingface': 'hf_AbCdEfGhIjKlMnOpQrStUvWxYz012345',
        'digitalocean': 'dop_v1_${'0af1' * 16}',
        'sendgrid': 'SG.AbCd1234EfGh5678.IjKl9012MnOp3456QrSt',
        'twilio': 'SK0123456789abcdef0123456789abcdef',
        'telegram': '123456789:AAAbCdEfGhIjKlMnOpQrStUvWxYz0123456',
      };
      cases.forEach((provider, token) {
        expect(found(d, 'key $token used'), [token],
            reason: '$provider token must match');
      });
    });
  });

  group('pem private keys', () {
    final d = Detectors.pemKey;
    test('matches a full PEM block as a single span', () {
      const block = '-----BEGIN RSA PRIVATE KEY-----\n'
          'MIIEpAIBAAKCAQEA7bq0\nx4dQ2mPq+ZZZ\n'
          '-----END RSA PRIVATE KEY-----';
      final matches = found(d, 'cfg:\n$block\ndone');
      expect(matches, [block]);
    });
    test('matches OpenSSH and unlabelled variants', () {
      const openssh = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n'
          '-----END OPENSSH PRIVATE KEY-----';
      const plain = '-----BEGIN PRIVATE KEY-----\nMIIE\n'
          '-----END PRIVATE KEY-----';
      expect(found(d, openssh), [openssh]);
      expect(found(d, plain), [plain]);
    });
    test('does not match certificates or public keys', () {
      const cert = '-----BEGIN CERTIFICATE-----\nMIIB\n'
          '-----END CERTIFICATE-----';
      const pub = '-----BEGIN PUBLIC KEY-----\nMIIB\n'
          '-----END PUBLIC KEY-----';
      expect(found(d, cert), isEmpty);
      expect(found(d, pub), isEmpty);
    });
  });

  group('url (opt-in)', () {
    final d = Detectors.url;
    test('is not part of the default set', () {
      expect(Detectors.defaults, isNot(contains(d)));
      expect(Detectors.all, contains(d));
    });
    test('matches http(s) links when enabled', () {
      expect(found(d, 'see https://example.com/x?y=1 today'),
          ['https://example.com/x?y=1']);
    });
  });
}
