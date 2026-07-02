import 'detector.dart';
import 'detectors.dart';
import 'pii_type.dart';

/// Opt-in, country-specific detector packs.
///
/// National ID formats are only meaningful for apps serving that region, so
/// none of these are in [Detectors.defaults] — prepend the pack you need:
///
/// ```dart
/// final redactor = Redactor(
///   detectors: [...DetectorPacks.pk, ...Detectors.defaults],
/// );
/// redactor.redact('CNIC 35202-1234567-1').text; // CNIC [PK_CNIC_1]
/// ```
///
/// Packs follow the same precision-first rules as the built-ins; more
/// countries are planned (see the README roadmap). Pack detectors emit
/// [PiiType.custom] matches with a country-prefixed label, so the [PiiType]
/// enum stays stable as packs grow.
abstract final class DetectorPacks {
  /// Pakistan 🇵🇰: CNIC national identity numbers, e.g. `35202-1234567-1`
  /// (5-7-1 digit grouping as printed on the card).
  static final List<Detector> pk = List.unmodifiable(<Detector>[
    PatternDetector(
      name: 'pk-cnic',
      type: PiiType.custom,
      pattern: RegExp(r'(?<![\d-])\d{5}-\d{7}-\d(?![\d-])'),
      label: 'PK_CNIC',
    ),
  ]);
}
