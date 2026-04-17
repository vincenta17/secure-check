// lib/services/api_service.dart
// ──────────────────────────────────────────────────────────────
// HTTP client that communicates with the Flask REST API.
// ──────────────────────────────────────────────────────────────

import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/api_config.dart';
import '../models/prediction_result.dart';
import '../models/dataset_stats.dart';

class ApiService {
  final http.Client _client = http.Client();

  Uri _uri(String path) => Uri.parse('${ApiConfig.baseUrl}$path');

  // ───── Health ─────

  Future<bool> healthCheck() async {
    try {
      final resp = await _client
          .get(_uri(ApiConfig.health))
          .timeout(ApiConfig.timeout);
      if (resp.statusCode == 200) {
        final body = jsonDecode(resp.body);
        return body['status'] == 'ok';
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  // ───── Predict ─────

  Future<PredictionResult> predict(String url) async {
    final resp = await _client
        .post(
          _uri(ApiConfig.predict),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'url': url}),
        )
        .timeout(ApiConfig.timeout);

    if (resp.statusCode == 200) {
      return PredictionResult.fromJson(jsonDecode(resp.body));
    } else {
      final body = jsonDecode(resp.body);
      throw Exception(body['error'] ?? 'Prediction failed');
    }
  }

  // ───── Stats ─────

  Future<DatasetStats> getStats() async {
    final resp = await _client
        .get(_uri(ApiConfig.stats))
        .timeout(ApiConfig.timeout);

    if (resp.statusCode == 200) {
      return DatasetStats.fromJson(jsonDecode(resp.body));
    } else {
      throw Exception('Failed to load stats');
    }
  }

  Future<Map<String, dynamic>> getModelInfo() async {
    final resp = await _client
        .get(_uri('/api/model/info'))
        .timeout(ApiConfig.timeout);

    if (resp.statusCode == 200) {
      return jsonDecode(resp.body);
    } else {
      throw Exception('Failed to load model info');
    }
  }

  // ───── Report / Add Data ─────

  Future<String> reportUrl(String url, String label) async {
    final resp = await _client
        .post(
          _uri(ApiConfig.datasetAdd),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'url': url, 'label': label}),
        )
        .timeout(ApiConfig.timeout);

    final body = jsonDecode(resp.body);
    if (resp.statusCode == 200) {
      return body['message'] ?? 'Success';
    } else {
      throw Exception(body['error'] ?? 'Report failed');
    }
  }

  // ───── Retrain ─────

  Future<String> retrainModel() async {
    final resp = await _client
        .post(_uri(ApiConfig.modelRetrain))
        .timeout(const Duration(minutes: 10));

    final body = jsonDecode(resp.body);
    if (resp.statusCode == 200) {
      return body['message'] ?? 'Retrained';
    } else {
      throw Exception(body['error'] ?? 'Retrain failed');
    }
  }

  void dispose() => _client.close();
}
