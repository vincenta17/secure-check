// lib/config/api_config.dart
// ──────────────────────────────────────────────────────────────
// Central API configuration. Change baseUrl to match your server.
// ──────────────────────────────────────────────────────────────

class ApiConfig {
  // ⚠️  Change this to your server IP when running on a real device.
  //     For Android emulator use 10.0.2.2 instead of 127.0.0.1.
  static const String baseUrl = 'http://192.168.0.114:8080';

  static const Duration timeout = Duration(seconds: 60);

  // Endpoints
  static const String predict = '/api/predict';
  static const String predictBatch = '/api/predict-batch';
  static const String health = '/api/health';
  static const String stats = '/api/stats';
  static const String datasetAdd = '/api/dataset/add';
  static const String modelRetrain = '/api/model/retrain';
}
