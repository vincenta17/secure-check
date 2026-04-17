import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import '../services/api_service.dart';
import '../models/dataset_stats.dart';

class StatsScreen extends StatefulWidget {
  const StatsScreen({super.key});

  @override
  State<StatsScreen> createState() => _StatsScreenState();
}

class _StatsScreenState extends State<StatsScreen> {
  final _api = ApiService();
  DatasetStats? _stats;
  Map<String, dynamic>? _modelInfo;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final s = await _api.getStats();
      final m = await _api.getModelInfo();
      setState(() {
        _stats = s;
        _modelInfo = m;
      });
    } catch (e) {
      setState(() => _error = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Intelligence Dashboard'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _load),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error != null
          ? Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(
                    Icons.cloud_off,
                    size: 56,
                    color: Color(0xFF9898B0),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'Could not load stats',
                    style: theme.textTheme.titleLarge,
                  ),
                  const SizedBox(height: 6),
                  Text(_error!, style: theme.textTheme.bodyMedium),
                  const SizedBox(height: 20),
                  ElevatedButton.icon(
                    onPressed: _load,
                    icon: const Icon(Icons.refresh, size: 18),
                    label: const Text('Retry'),
                  ),
                ],
              ),
            )
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  if (_modelInfo != null) ...[
                    _SectionTitle(title: '🌟 AI Architecture Intelligence'),
                    const SizedBox(height: 8),
                    _ModelIntelligenceCard(info: _modelInfo!),
                    const SizedBox(height: 24),
                  ],

                  // ── Total card ──
                  _SectionTitle(title: 'Dataset Metrics'),
                  const SizedBox(height: 8),
                  _TotalCard(stats: _stats!),
                  const SizedBox(height: 16),

                  // ── Pie chart ──
                  _SectionTitle(title: 'Classification Distribution'),
                  const SizedBox(height: 8),
                  _PieChartCard(stats: _stats!),
                  const SizedBox(height: 16),

                  // ── Domain age ──
                  _SectionTitle(title: 'Domain Age'),
                  const SizedBox(height: 8),
                  _BarRow(
                    items: [
                      _BarItem(
                        'New (<1yr)',
                        _stats!.domainNew,
                        const Color(0xFFFFA726),
                      ),
                      _BarItem(
                        'Established',
                        _stats!.domainEstablished,
                        const Color(0xFF42A5F5),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // ── Response time ──
                  _SectionTitle(title: 'Response Time'),
                  const SizedBox(height: 8),
                  _BarRow(
                    items: [
                      _BarItem(
                        'Fast',
                        _stats!.responseFast,
                        const Color(0xFF00D9A6),
                      ),
                      _BarItem(
                        'Medium',
                        _stats!.responseMedium,
                        const Color(0xFFFFA726),
                      ),
                      _BarItem(
                        'Slow',
                        _stats!.responseSlow,
                        const Color(0xFFFF5252),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // ── SSL ──
                  _SectionTitle(title: 'SSL / TLS'),
                  const SizedBox(height: 8),
                  _InfoTile(
                    icon: Icons.lock,
                    label: 'URLs with SSL',
                    value: '${_stats!.sslCount}',
                    color: const Color(0xFF00D9A6),
                  ),
                  const SizedBox(height: 40),
                ],
              ),
            ),
    );
  }
}

class _ModelIntelligenceCard extends StatelessWidget {
  final Map<String, dynamic> info;
  const _ModelIntelligenceCard({required this.info});

  @override
  Widget build(BuildContext context) {
    final bestModel = info['best_model'] ?? 'Unknown';
    final modelResults = info['model_results'] as Map<String, dynamic>? ?? {};
    final bestStats = modelResults[bestModel] as Map<String, dynamic>? ?? {};
    final accuracy = (bestStats['accuracy'] as num?)?.toDouble() ?? 0.0;
    
    final features = info['feature_importance'] as List<dynamic>? ?? [];

    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF1E1E28),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFF6C63FF).withValues(alpha: 0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF6C63FF).withValues(alpha: 0.15),
              borderRadius: const BorderRadius.vertical(top: Radius.circular(16)),
            ),
            child: Row(
              children: [
                const Icon(Icons.psychology, color: Color(0xFF6C63FF), size: 32),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Active Core Model',
                        style: TextStyle(color: Color(0xFFD0D0E0), fontSize: 12),
                      ),
                      Text(
                        bestModel.replaceAll('_', ' '),
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                ),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    const Text('Accuracy', style: TextStyle(color: Color(0xFF00D9A6), fontSize: 12)),
                    Text(
                      '${(accuracy * 100).toStringAsFixed(1)}%',
                      style: const TextStyle(
                        color: Color(0xFF00D9A6),
                        fontSize: 20,
                        fontWeight: FontWeight.w900,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Top 5 Crucial URL Features',
                  style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 12),
                ...features.take(5).map((f) {
                  final name = f['feature'] as String;
                  final importance = (f['importance'] as num).toDouble();
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Row(
                      children: [
                        Icon(Icons.auto_awesome, size: 16, color: const Color(0xFFFFB74D)),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            name.replaceAll('_', ' '),
                            style: const TextStyle(color: Color(0xFFD0D0E0), fontSize: 13),
                          ),
                        ),
                        Text(
                          '${(importance * 100).toStringAsFixed(1)}%',
                          style: const TextStyle(color: Color(0xFF9898B0), fontSize: 12),
                        ),
                      ],
                    ),
                  );
                }),
              ],
            ),
          ),
        ],
      ),
    );
  }
}


// ──────────────────────────────────────────────────────────────
// Widgets
// ──────────────────────────────────────────────────────────────

class _SectionTitle extends StatelessWidget {
  final String title;
  const _SectionTitle({required this.title});

  @override
  Widget build(BuildContext context) {
    return Text(title, style: Theme.of(context).textTheme.titleMedium);
  }
}

class _TotalCard extends StatelessWidget {
  final DatasetStats stats;
  const _TotalCard({required this.stats});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(18),
        gradient: LinearGradient(
          colors: [
            const Color(0xFF6C63FF).withValues(alpha: 0.2),
            const Color(0xFF00D9A6).withValues(alpha: 0.08),
          ],
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceAround,
        children: [
          _StatColumn('Total', stats.total, const Color(0xFFE8E8F0)),
          _StatColumn('Phishing', stats.phishing, const Color(0xFFFF5252)),
          _StatColumn('Legitimate', stats.legitimate, const Color(0xFF00D9A6)),
        ],
      ),
    );
  }
}

class _StatColumn extends StatelessWidget {
  final String label;
  final int value;
  final Color color;
  const _StatColumn(this.label, this.value, this.color);

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(
          _formatNum(value),
          style: TextStyle(
            fontSize: 24,
            fontWeight: FontWeight.w700,
            color: color,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: const TextStyle(fontSize: 12, color: Color(0xFF9898B0)),
        ),
      ],
    );
  }

  String _formatNum(int n) {
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(1)}K';
    return n.toString();
  }
}

class _PieChartCard extends StatelessWidget {
  final DatasetStats stats;
  const _PieChartCard({required this.stats});

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 200,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        children: [
          Expanded(
            child: PieChart(
              PieChartData(
                sectionsSpace: 3,
                centerSpaceRadius: 30,
                sections: [
                  PieChartSectionData(
                    value: stats.phishing.toDouble(),
                    color: const Color(0xFFFF5252),
                    title:
                        '${(stats.phishing / stats.total * 100).toStringAsFixed(1)}%',
                    titleStyle: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: Colors.white,
                    ),
                    radius: 40,
                  ),
                  PieChartSectionData(
                    value: stats.legitimate.toDouble(),
                    color: const Color(0xFF00D9A6),
                    title:
                        '${(stats.legitimate / stats.total * 100).toStringAsFixed(1)}%',
                    titleStyle: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: Colors.white,
                    ),
                    radius: 40,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(width: 20),
          Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _LegendDot('Phishing', const Color(0xFFFF5252)),
              const SizedBox(height: 10),
              _LegendDot('Legitimate', const Color(0xFF00D9A6)),
            ],
          ),
        ],
      ),
    );
  }
}

class _LegendDot extends StatelessWidget {
  final String label;
  final Color color;
  const _LegendDot(this.label, this.color);

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          width: 12,
          height: 12,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 8),
        Text(
          label,
          style: const TextStyle(fontSize: 13, color: Color(0xFF9898B0)),
        ),
      ],
    );
  }
}

class _BarItem {
  final String label;
  final int value;
  final Color color;
  const _BarItem(this.label, this.value, this.color);
}

class _BarRow extends StatelessWidget {
  final List<_BarItem> items;
  const _BarRow({required this.items});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        children: items.map((item) {
          return Expanded(
            child: Column(
              children: [
                Text(
                  _fmt(item.value),
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.w700,
                    color: item.color,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  item.label,
                  style: const TextStyle(
                    fontSize: 12,
                    color: Color(0xFF9898B0),
                  ),
                ),
              ],
            ),
          );
        }).toList(),
      ),
    );
  }

  String _fmt(int n) {
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(1)}K';
    return n.toString();
  }
}

class _InfoTile extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final Color color;
  const _InfoTile({
    required this.icon,
    required this.label,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(icon, color: color),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Text(
              label,
              style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
            ),
          ),
          Text(
            value,
            style: TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.w700,
              color: color,
            ),
          ),
        ],
      ),
    );
  }
}
