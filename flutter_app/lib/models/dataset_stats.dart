// lib/models/dataset_stats.dart
// ──────────────────────────────────────────────────────────────
// Data model for dataset statistics from the API.
// ──────────────────────────────────────────────────────────────

class DatasetStats {
  final int total;
  final int phishing;
  final int legitimate;
  final int sslCount;
  final int domainNew;
  final int domainEstablished;
  final int responseFast;
  final int responseMedium;
  final int responseSlow;

  DatasetStats({
    required this.total,
    required this.phishing,
    required this.legitimate,
    required this.sslCount,
    required this.domainNew,
    required this.domainEstablished,
    required this.responseFast,
    required this.responseMedium,
    required this.responseSlow,
  });

  factory DatasetStats.fromJson(Map<String, dynamic> json) {
    final domainAge = json['domain_age'] as Map<String, dynamic>? ?? {};
    final respTime  = json['response_time'] as Map<String, dynamic>? ?? {};

    return DatasetStats(
      total: json['total'] as int? ?? 0,
      phishing: json['phishing'] as int? ?? 0,
      legitimate: json['legitimate'] as int? ?? 0,
      sslCount: json['ssl_count'] as int? ?? 0,
      domainNew: domainAge['new'] as int? ?? 0,
      domainEstablished: domainAge['established'] as int? ?? 0,
      responseFast: respTime['fast'] as int? ?? 0,
      responseMedium: respTime['medium'] as int? ?? 0,
      responseSlow: respTime['slow'] as int? ?? 0,
    );
  }
}
