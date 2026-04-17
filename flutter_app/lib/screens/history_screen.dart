// lib/screens/history_screen.dart
// ──────────────────────────────────────────────────────────────
// View past URL scan results stored locally.
// Auto-refreshes when the tab becomes visible.
// ──────────────────────────────────────────────────────────────

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../services/storage_service.dart';
import '../models/prediction_result.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen>
    with WidgetsBindingObserver {
  final _storage = StorageService();
  List<PredictionResult> _history = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _load();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  // Auto-refresh when app resumes or tab changes
  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _load();
  }

  Future<void> _load() async {
    final data = await _storage.getHistory();
    if (mounted) {
      setState(() {
        _history = data;
        _loading = false;
      });
    }
  }

  Future<void> _clearAll() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Clear History'),
        content: const Text('Delete all scan history? This cannot be undone.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Clear', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await _storage.clearHistory();
      _load();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan History'),
        actions: [
          // Refresh button — always visible
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () {
              setState(() => _loading = true);
              _load();
            },
          ),
          if (_history.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_outline),
              tooltip: 'Clear all',
              onPressed: _clearAll,
            ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _history.isEmpty
          ? Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.history,
                    size: 64,
                    color: theme.colorScheme.primary.withValues(alpha: 0.3),
                  ),
                  const SizedBox(height: 16),
                  Text('No scans yet', style: theme.textTheme.titleLarge),
                  const SizedBox(height: 6),
                  Text(
                    'Scan a URL on the Check tab to see results here.',
                    style: theme.textTheme.bodyMedium,
                  ),
                  const SizedBox(height: 24),
                  ElevatedButton.icon(
                    onPressed: () {
                      setState(() => _loading = true);
                      _load();
                    },
                    icon: const Icon(Icons.refresh),
                    label: const Text('Refresh'),
                  ),
                ],
              ),
            )
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView.separated(
                padding: const EdgeInsets.all(16),
                itemCount: _history.length,
                separatorBuilder: (_, __) => const SizedBox(height: 10),
                itemBuilder: (_, i) => _HistoryTile(result: _history[i]),
              ),
            ),
    );
  }
}

class _HistoryTile extends StatelessWidget {
  final PredictionResult result;
  const _HistoryTile({required this.result});

  @override
  Widget build(BuildContext context) {
    final isPhishing = result.isPhishing;
    final color = isPhishing
        ? const Color(0xFFFF5252)
        : const Color(0xFF00D9A6);
    final icon = isPhishing ? Icons.warning_amber_rounded : Icons.verified_user;
    final df = DateFormat('dd MMM yyyy, HH:mm');

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withValues(alpha: 0.2)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, color: color, size: 24),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  result.url,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 4),
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 3,
                      ),
                      decoration: BoxDecoration(
                        color: color.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        result.classification.toUpperCase(),
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          color: color,
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      df.format(result.checkedAt),
                      style: const TextStyle(
                        fontSize: 11,
                        color: Color(0xFF9898B0),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          if (result.confidence != null)
            Text(
              '${(result.confidence! * 100).toStringAsFixed(0)}%',
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w600,
                color: color,
              ),
            ),
        ],
      ),
    );
  }
}
