// lib/models/prediction_result.dart
class SourceResult {
  final String name;
  final bool available;
  final String verdict;
  final double? confidence;
  final String? model;
  final String? details;
  final int? detections;
  final int? totalEngines;
  final List<String>? threats;

  SourceResult({
    required this.name,
    required this.available,
    required this.verdict,
    this.confidence,
    this.model,
    this.details,
    this.detections,
    this.totalEngines,
    this.threats,
  });

  bool get isPhishing => verdict == 'phishing' || verdict == 'suspicious';
}

class PredictionResult {
  final String url;
  final String classification;
  final double? confidence;
  final int sourcesUsed;
  final SourceResult? mlSource;
  final SourceResult? vtSource;
  final SourceResult? sbSource;
  final List<String> anomalies;
  final DateTime checkedAt;

  PredictionResult({
    required this.url,
    required this.classification,
    this.confidence,
    this.sourcesUsed = 1,
    this.mlSource,
    this.vtSource,
    this.sbSource,
    this.anomalies = const [],
    DateTime? checkedAt,
  }) : checkedAt = checkedAt ?? DateTime.now();

  bool get isPhishing => classification == 'phishing';

  factory PredictionResult.fromJson(Map<String, dynamic> json) {
    final sources = json['sources'] as Map<String, dynamic>? ?? {};

    SourceResult? ml;
    if (sources.containsKey('ml_model')) {
      final m = sources['ml_model'] as Map<String, dynamic>;
      ml = SourceResult(
        name: 'AI Model',
        available: true,
        verdict: m['verdict'] as String? ?? 'unknown',
        confidence: (m['confidence'] as num?)?.toDouble(),
        model: m['model'] as String?,
      );
    }

    SourceResult? vt;
    if (sources.containsKey('virustotal')) {
      final m = sources['virustotal'] as Map<String, dynamic>;
      vt = SourceResult(
        name: 'VirusTotal',
        available: m['available'] as bool? ?? false,
        verdict: m['verdict'] as String? ?? 'unknown',
        details: m['details'] as String?,
        detections: m['malicious'] as int?,
        totalEngines: m['total_engines'] as int?,
      );
    }

    SourceResult? sb;
    if (sources.containsKey('safe_browsing')) {
      final m = sources['safe_browsing'] as Map<String, dynamic>;
      sb = SourceResult(
        name: 'Safe Browsing',
        available: m['available'] as bool? ?? false,
        verdict: m['verdict'] as String? ?? 'unknown',
        details: m['details'] as String?,
        threats: (m['threats'] as List<dynamic>?)?.map((e) => e.toString()).toList(),
      );
    }

    final rawAnomalies = json['anomalies'] as List<dynamic>? ?? [];

    return PredictionResult(
      url: json['url'] as String? ?? '',
      classification: json['classification'] as String? ?? 'unknown',
      confidence: (json['confidence'] as num?)?.toDouble(),
      sourcesUsed: json['sources_used'] as int? ?? 1,
      mlSource: ml,
      vtSource: vt,
      sbSource: sb,
      anomalies: rawAnomalies.map((e) => e.toString()).toList(),
    );
  }

  Map<String, dynamic> toJson() => {
        'url': url,
        'classification': classification,
        'confidence': confidence,
        'sourcesUsed': sourcesUsed,
        'mlVerdict': mlSource?.verdict,
        'mlModel': mlSource?.model,
        'mlConfidence': mlSource?.confidence,
        'vtAvailable': vtSource?.available,
        'vtVerdict': vtSource?.verdict,
        'vtDetails': vtSource?.details,
        'vtDetections': vtSource?.detections,
        'vtTotal': vtSource?.totalEngines,
        'sbAvailable': sbSource?.available,
        'sbVerdict': sbSource?.verdict,
        'sbDetails': sbSource?.details,
        'anomalies': anomalies,
        'checkedAt': checkedAt.toIso8601String(),
      };

  factory PredictionResult.fromStorageJson(Map<String, dynamic> json) {
    SourceResult? ml;
    if (json['mlVerdict'] != null) {
      ml = SourceResult(
        name: 'AI Model',
        available: true,
        verdict: json['mlVerdict'] as String? ?? 'unknown',
        confidence: (json['mlConfidence'] as num?)?.toDouble(),
        model: json['mlModel'] as String?,
      );
    }

    SourceResult? vt;
    if (json['vtAvailable'] != null) {
      vt = SourceResult(
        name: 'VirusTotal',
        available: json['vtAvailable'] as bool? ?? false,
        verdict: json['vtVerdict'] as String? ?? 'unknown',
        details: json['vtDetails'] as String?,
        detections: json['vtDetections'] as int?,
        totalEngines: json['vtTotal'] as int?,
      );
    }

    SourceResult? sb;
    if (json['sbAvailable'] != null) {
      sb = SourceResult(
        name: 'Safe Browsing',
        available: json['sbAvailable'] as bool? ?? false,
        verdict: json['sbVerdict'] as String? ?? 'unknown',
        details: json['sbDetails'] as String?,
      );
    }

    final rawAnomalies = json['anomalies'] as List<dynamic>? ?? [];

    return PredictionResult(
      url: json['url'] as String? ?? '',
      classification: json['classification'] as String? ?? 'unknown',
      confidence: (json['confidence'] as num?)?.toDouble(),
      sourcesUsed: json['sourcesUsed'] as int? ?? 1,
      mlSource: ml,
      vtSource: vt,
      sbSource: sb,
      anomalies: rawAnomalies.map((e) => e.toString()).toList(),
      checkedAt: DateTime.tryParse(json['checkedAt'] ?? '') ?? DateTime.now(),
    );
  }
}

