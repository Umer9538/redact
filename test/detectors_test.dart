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
  });

  group('phone', () {
    final d = Detectors.phone;
    test('matches structured numbers', () {
      expect(found(d, 'call +1 415-555-0132 now'), ['+1 415-555-0132']);
      expect(found(d, 'tel (020) 7946 0958'), ['(020) 7946 0958']);
      expect(found(d, 'ph 415.555.0199'), ['415.555.0199']);
    });
    test('ignores bare digit runs and too-short/long sequences', () {
      expect(found(d, 'order 1234567890123456 shipped'), isEmpty);
      expect(found(d, 'room 12-34'), isEmpty); // only 4 digits
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
    test('rejects check-digit-invalid IBANs', () {
      expect(found(d, 'GB00 WEST 1234 5698 7654 32'), isEmpty);
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
