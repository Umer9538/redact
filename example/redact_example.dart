// Run with: dart run example/redact_example.dart
//
// Demonstrates the four things `redact` is for:
//   1. Scrubbing PII out of text before it reaches an LLM.
//   2. The reversible pipeline: redact -> call the model -> restore the reply.
//   3. Per-category styles (mask a card, placeholder everything else).
//   4. Extending detection with your own domain-specific Detector.

import 'package:redact/redact.dart';

void main() {
  _basic();
  _reversiblePipeline();
  _perCategoryStyles();
  _customDetector();
}

void _basic() {
  print('== 1. Scrub before sending ==');
  final redactor = Redactor();
  final result = redactor.redact(
    'Hi, I am Jane. Email jane@acme.com or call +1 415-555-0132. '
    'Card 4111 1111 1111 1111.',
  );
  print(result.text);
  print('Detected ${result.count} item(s): '
      '${result.types.map((t) => t.name).join(', ')}\n');
}

void _reversiblePipeline() {
  print('== 2. Reversible pipeline ==');
  final redactor = Redactor();
  const userMessage = 'Reset the account for john.doe@example.com please.';

  final result = redactor.redact(userMessage);
  print('Sent to model : ${result.text}');

  // The model only ever sees placeholders; it echoes them back.
  final modelReply = _fakeLlm(result.text);
  print('Model replied : $modelReply');

  final restored = result.restore(modelReply);
  print('Shown to user : $restored\n');
}

void _perCategoryStyles() {
  print('== 3. Per-category styles ==');
  final redactor = Redactor(
    styleOverrides: {PiiType.creditCard: RedactionStyle.mask},
  );
  final result = redactor.redact(
    'Charge 5500 0055 5555 5559 and email the receipt to a@b.com',
  );
  print('${result.text}\n');
}

void _customDetector() {
  print('== 4. Custom detector ==');
  // A hospital-specific medical record number, e.g. "MRN-004512".
  final mrn = PatternDetector(
    name: 'mrn',
    type: PiiType.custom,
    pattern: RegExp(r'\bMRN-\d{4,8}\b'),
    label: 'PATIENT_ID',
  );
  final redactor = Redactor(detectors: [mrn, ...Detectors.defaults]);
  final result =
      redactor.redact('Patient MRN-004512 booked with dr@clinic.org');
  print(result.text);
}

/// A stand-in for a real LLM call. It just echoes a placeholder it was given,
/// proving the model never touches the original PII.
String _fakeLlm(String prompt) {
  final token = RegExp(r'\[EMAIL_\d+\]').firstMatch(prompt)?.group(0) ?? '';
  return 'Done. A reset link was sent to $token.';
}
