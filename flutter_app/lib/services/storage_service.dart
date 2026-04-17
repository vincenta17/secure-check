// lib/services/storage_service.dart
// ──────────────────────────────────────────────────────────────
// Local persistence for scan history using SharedPreferences.
// ──────────────────────────────────────────────────────────────

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/prediction_result.dart';

class StorageService {
  static const _key = 'scan_history';
  static const _maxItems = 200;

  Future<List<PredictionResult>> getHistory() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? [];
    return raw
        .map((s) => PredictionResult.fromStorageJson(jsonDecode(s)))
        .toList()
        .reversed
        .toList(); // newest first
  }

  Future<void> addResult(PredictionResult result) async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? [];
    raw.add(jsonEncode(result.toJson()));
    // Keep only the last _maxItems
    if (raw.length > _maxItems) {
      raw.removeRange(0, raw.length - _maxItems);
    }
    await prefs.setStringList(_key, raw);
  }

  Future<void> clearHistory() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }
}
