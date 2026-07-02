// Benchmark: redact() over ~1MB synthetic chat text + per-prompt latency.
// Deterministic (seeded RNG).
//
// JIT: dart run benchmark/bench.dart
// AOT (matches Flutter release mode):
//   dart compile exe benchmark/bench.dart -o /tmp/bench && /tmp/bench
import 'dart:math';

import 'package:redact/redact.dart';

const _plainLines = [
  'hey can you summarize the meeting notes from yesterday',
  'I think we should refactor the onboarding flow before the release',
  'what time works for the standup tomorrow morning',
  'the build is green again after reverting that commit',
  'can you draft a reply to the customer about the delayed shipment',
  'let me know when the design review doc is ready to share',
  'we saw a spike in crashes on Android 14 devices after the update',
  'please rewrite this paragraph to sound more formal but keep it short',
  'the quarterly numbers look better than expected honestly',
  'remind me to renew the certificates before the end of the month',
  'I pushed the fix, waiting on CI, should be done in ten minutes',
  'thoughts on switching the caching layer to something simpler',
];

// PII payload templates. Card + IBAN values are checksum-valid so the
// validators actually accept them (that is the realistic hot path).
const _cards = [
  '4111 1111 1111 1111',
  '5555-5555-5555-4444',
  '378282246310005'
];
const _ibans = ['DE89 3704 0044 0532 0130 00', 'GB82WEST12345698765432'];
const _ssns = ['536-90-4399', '212-09-9999'];

String _email(Random r) =>
    'user${r.nextInt(9000) + 1000}@example${r.nextInt(90)}.com';
String _phone(Random r) =>
    '+1 ${r.nextInt(800) + 200}-${r.nextInt(900) + 100}-${r.nextInt(9000) + 1000}';
String _ip(Random r) =>
    '${r.nextInt(223) + 1}.${r.nextInt(256)}.${r.nextInt(256)}.${r.nextInt(255)}';

String _piiLine(Random r) {
  switch (r.nextInt(8)) {
    case 0:
      return 'reach me at ${_email(r)} whenever you get a chance';
    case 1:
      return 'call the customer back on ${_phone(r)} before noon';
    case 2:
      return 'the card on file is ${_cards[r.nextInt(_cards.length)]} expiring soon';
    case 3:
      return 'wire the refund to ${_ibans[r.nextInt(_ibans.length)]} today';
    case 4:
      return 'applicant SSN is ${_ssns[r.nextInt(_ssns.length)]} for the form';
    case 5:
      return 'the server at ${_ip(r)} stopped responding overnight';
    case 6:
      return 'token sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8t got committed by mistake';
    default:
      return 'send the invoice to ${_email(r)} and cc ${_email(r)}';
  }
}

String buildCorpus(int targetBytes, {double piiRate = 0.12, int seed = 42}) {
  final r = Random(seed);
  final b = StringBuffer();
  while (b.length < targetBytes) {
    b
      ..write(r.nextDouble() < piiRate
          ? _piiLine(r)
          : _plainLines[r.nextInt(_plainLines.length)])
      ..write(r.nextInt(4) == 0 ? '\n' : ' ');
  }
  return b.toString();
}

String build500CharPrompt() {
  final base = 'Hi, I need help drafting an email. My colleague Jane can be '
      'reached at jane.doe@acme-corp.com or on +1 415-555-0132 if anything is '
      'unclear. Context: our customer ordered the premium plan and paid with '
      'card 4111 1111 1111 1111, but the invoice was never delivered and they '
      'are understandably frustrated. Please write a short, sincere apology '
      'that confirms the refund is processed, offers a discount on the next '
      'renewal, and keeps a professional but warm tone throughout the reply.';
  return base.padRight(500, ' x').substring(0, 500);
}

String build500CharCleanPrompt() {
  final base = 'Please rewrite the following product description so it is '
      'clearer and more persuasive for a general audience. Keep it under one '
      'hundred and fifty words, avoid jargon, and emphasise reliability and '
      'ease of use. The product is a smart thermostat that learns household '
      'routines, integrates with common voice assistants, and reduces energy '
      'bills by adapting heating and cooling schedules automatically over '
      'time. End with a single call to action encouraging the reader to learn '
      'more on the website today. Thanks so much for the help with this one.';
  return base.padRight(500, ' x').substring(0, 500);
}

void main() {
  final redactor = Redactor();

  // ---- corpus benchmark ----
  final corpus = buildCorpus(1024 * 1024);
  final mb = corpus.length / (1024 * 1024);

  // Warmup.
  for (var i = 0; i < 3; i++) {
    redactor.redact(corpus);
  }

  const runs = 10;
  final times = <double>[];
  late RedactionResult res;
  for (var i = 0; i < runs; i++) {
    final sw = Stopwatch()..start();
    res = redactor.redact(corpus);
    sw.stop();
    times.add(sw.elapsedMicroseconds / 1000.0); // ms
  }
  times.sort();
  final median = times[times.length ~/ 2];
  final best = times.first;

  print('corpus: ${corpus.length} chars (${mb.toStringAsFixed(2)} MB)');
  print('matches found: ${res.count} across ${res.types.length} types');
  print('redact() median: ${median.toStringAsFixed(1)} ms  '
      '(best ${best.toStringAsFixed(1)} ms, runs=$runs)');
  print('throughput: ${(mb / (median / 1000)).toStringAsFixed(2)} MB/s  '
      '(${(corpus.length / (median / 1000) / 1e6).toStringAsFixed(2)} M chars/s)');

  // ---- 500-char prompt latency ----
  for (final (label, prompt) in [
    ('500-char prompt with PII (email+phone+card)', build500CharPrompt()),
    ('500-char prompt, no PII', build500CharCleanPrompt()),
  ]) {
    // Warmup.
    for (var i = 0; i < 2000; i++) {
      redactor.redact(prompt);
    }
    const iters = 20000;
    final sw = Stopwatch()..start();
    var totalMatches = 0;
    for (var i = 0; i < iters; i++) {
      totalMatches += redactor.redact(prompt).count;
    }
    sw.stop();
    final usPer = sw.elapsedMicroseconds / iters;
    print('$label: ${usPer.toStringAsFixed(1)} us/call '
        '(${(usPer / 1000).toStringAsFixed(3)} ms), '
        'matches/call=${totalMatches ~/ iters}');
  }
}
