/// Returns whether [digits] satisfies the Luhn (mod 10) checksum.
///
/// Used to keep credit-card detection precision-first: a 13–19 digit run that
/// merely *looks* like a card but fails Luhn (an order number, say) is rejected
/// rather than redacted. Any non-digit characters in [digits] are ignored, so
/// grouped inputs like `4111 1111 1111 1111` validate directly.
///
/// Returns `false` for input with fewer than two digits.
bool isLuhnValid(String digits) {
  var sum = 0;
  var count = 0;
  var alternate = false;

  // Walk right-to-left so the doubling parity is anchored to the last digit.
  for (var i = digits.length - 1; i >= 0; i--) {
    final code = digits.codeUnitAt(i);
    if (code < 0x30 || code > 0x39) continue; // skip non-digits
    var n = code - 0x30;
    count++;
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }

  if (count < 2) return false;
  return sum % 10 == 0;
}
