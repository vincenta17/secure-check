// lib/screens/home_screen.dart
import 'package:flutter/material.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../models/prediction_result.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen>
    with SingleTickerProviderStateMixin {
  final _urlCtrl = TextEditingController();
  final _api = ApiService();
  final _storage = StorageService();

  bool _loading = false;
  PredictionResult? _result;
  String? _error;

  late AnimationController _animCtrl;
  late Animation<double> _scaleAnim;

  @override
  void initState() {
    super.initState();
    _animCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 600),
    );
    _scaleAnim = CurvedAnimation(parent: _animCtrl, curve: Curves.elasticOut);
  }

  @override
  void dispose() {
    _animCtrl.dispose();
    _urlCtrl.dispose();
    super.dispose();
  }

  Future<void> _checkUrl() async {
    final url = _urlCtrl.text.trim();
    if (url.isEmpty) return;

    setState(() {
      _loading = true;
      _result = null;
      _error = null;
    });

    try {
      final result = await _api.predict(url);
      await _storage.addResult(result);
      setState(() => _result = result);
      _animCtrl.forward(from: 0);
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
      appBar: AppBar(title: const Text('Secure Check')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const SizedBox(height: 12),

            // ── Header ──
            Center(
              child: Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: LinearGradient(
                    colors: [
                      theme.colorScheme.primary.withValues(alpha: 0.3),
                      theme.colorScheme.secondary.withValues(alpha: 0.15),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                ),
                child: Icon(
                  Icons.psychology, // AI Brain icon
                  size: 48,
                  color: theme.colorScheme.primary,
                ),
              ),
            ),
            const SizedBox(height: 20),
            Text(
              'Hyper-Accurate AI Check',
              textAlign: TextAlign.center,
              style: theme.textTheme.headlineMedium,
            ),
            const SizedBox(height: 6),
            Text(
              'Powered by Stacking Ensemble ML Model',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 28),

            // ── Input ──
            TextField(
              controller: _urlCtrl,
              keyboardType: TextInputType.url,
              textInputAction: TextInputAction.go,
              onSubmitted: (_) => _checkUrl(),
              decoration: const InputDecoration(
                hintText: 'https://example.com',
                prefixIcon: Icon(Icons.link),
              ),
            ),
            const SizedBox(height: 16),

            // ── Button ──
            SizedBox(
              height: 54,
              child: ElevatedButton(
                onPressed: _loading ? null : _checkUrl,
                child: _loading
                    ? const SizedBox(
                        width: 24,
                        height: 24,
                        child: CircularProgressIndicator(
                          strokeWidth: 2.5,
                          color: Colors.white,
                        ),
                      )
                    : const Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(Icons.search, size: 22),
                          SizedBox(width: 8),
                          Text('Analyze URL'),
                        ],
                      ),
              ),
            ),
            const SizedBox(height: 28),

            // ── Error ──
            if (_error != null) _ErrorCard(message: _error!),

            // ── Result ──
            if (_result != null)
              ScaleTransition(
                scale: _scaleAnim,
                child: _AIResultCard(result: _result!),
              ),
          ],
        ),
      ),
    );
  }
}

class _AIResultCard extends StatelessWidget {
  final PredictionResult result;
  const _AIResultCard({required this.result});

  @override
  Widget build(BuildContext context) {
    final isPhishing = result.isPhishing;
    final color =
        isPhishing ? const Color(0xFFFF5252) : const Color(0xFF00D9A6);
    final icon =
        isPhishing ? Icons.warning_amber_rounded : Icons.verified_user;
    final label = isPhishing ? 'PHISHING' : 'LEGITIMATE';
    final subtitle = isPhishing
        ? 'This URL shows signs of phishing. Do NOT enter personal information!'
        : 'This URL appears to be safe. Stay cautious anyway.';

    return Column(
      children: [
        // ── Main verdict card ──
        Container(
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(20),
            gradient: LinearGradient(
              colors: [
                color.withValues(alpha: 0.15),
                color.withValues(alpha: 0.05),
              ],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            border: Border.all(color: color.withValues(alpha: 0.3)),
          ),
          child: Column(
            children: [
              Icon(icon, size: 56, color: color),
              const SizedBox(height: 14),
              Text(
                label,
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w700,
                  color: color,
                ),
              ),
              if (result.confidence != null) ...[
                const SizedBox(height: 6),
                Text(
                  'AI Confidence: ${(result.confidence! * 100).toStringAsFixed(1)}%',
                  style: TextStyle(
                    fontSize: 15,
                    color: color.withValues(alpha: 0.8),
                  ),
                ),
              ],
              const SizedBox(height: 12),
              Text(
                subtitle,
                textAlign: TextAlign.center,
                style:
                    const TextStyle(fontSize: 14, color: Color(0xFF9898B0)),
              ),
              const SizedBox(height: 12),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                decoration: BoxDecoration(
                  color: const Color(0xFF121218),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  result.url,
                  style: const TextStyle(
                      fontSize: 13, color: Color(0xFF9898B0)),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
        ),

        const SizedBox(height: 16),

        // ── AI Model Details and Explainable AI (XAI) ──
        if (result.mlSource != null)
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surface,
              borderRadius: BorderRadius.circular(16),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Detection Intelligence',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                    color: Color(0xFFE8E8F0),
                  ),
                ),
                const SizedBox(height: 12),
                _SourceTile(
                  icon: Icons.psychology,
                  name: result.mlSource!.model ?? 'Advanced AI Model',
                  verdict: result.mlSource!.verdict,
                  detail: 'Predicted using 87 distinct URL features',
                ),

                // Explainable AI List
                if (result.anomalies.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  const Divider(color: Color(0xFF2A2A35)),
                  const SizedBox(height: 12),
                  const Row(
                    children: [
                      Icon(Icons.lightbulb_outline, size: 20, color: Color(0xFFFFB74D)),
                      SizedBox(width: 8),
                      Text(
                        'AI Explanation (Anomaly Detected):',
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                          color: Color(0xFFFFB74D),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  ...result.anomalies.map((anomaly) => Padding(
                        padding: const EdgeInsets.only(bottom: 6),
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text('•', style: TextStyle(color: Color(0xFFFF5252), fontSize: 16)),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                anomaly,
                                style: const TextStyle(
                                  fontSize: 13,
                                  color: Color(0xFFD0D0E0),
                                  height: 1.4,
                                ),
                              ),
                            ),
                          ],
                        ),
                      )),
                ],

                // External APIs Validation
                if (result.vtSource != null || result.sbSource != null) ...[
                  const SizedBox(height: 16),
                  const Divider(color: Color(0xFF2A2A35)),
                  const SizedBox(height: 12),
                  const Text(
                    'Global Validation Sources:',
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: Color(0xFFE8E8F0),
                    ),
                  ),
                  const SizedBox(height: 10),
                  
                  if (result.vtSource != null)
                    _SourceTile(
                      icon: Icons.bug_report,
                      name: 'VirusTotal',
                      verdict: result.vtSource!.verdict,
                      detail: result.vtSource!.available
                          ? '${result.vtSource!.detections}/${result.vtSource!.totalEngines} engines'
                          : result.vtSource!.details,
                    ),

                  if (result.vtSource != null && result.sbSource != null)
                    const SizedBox(height: 8),

                  if (result.sbSource != null)
                    _SourceTile(
                      icon: Icons.shield,
                      name: 'Google Safe Browsing',
                      verdict: result.sbSource!.verdict,
                      detail: result.sbSource!.available
                          ? (result.sbSource!.threats != null && result.sbSource!.threats!.isNotEmpty
                              ? result.sbSource!.threats!.join(', ')
                              : 'No threats found')
                          : result.sbSource!.details,
                    ),
                ],
              ],
            ),
          ),
      ],
    );
  }
}



class _SourceTile extends StatelessWidget {
  final IconData icon;
  final String name;
  final String verdict;
  final String? detail;

  const _SourceTile({
    required this.icon,
    required this.name,
    required this.verdict,
    this.detail,
  });

  @override
  Widget build(BuildContext context) {
    Color badgeColor;
    IconData badgeIcon;
    String badgeText;

    if (verdict == 'phishing' || verdict == 'suspicious') {
      badgeColor = const Color(0xFFFF5252);
      badgeIcon = Icons.dangerous;
      badgeText = verdict.toUpperCase();
    } else {
      badgeColor = const Color(0xFF00D9A6);
      badgeIcon = Icons.check_circle;
      badgeText = 'SAFE';
    }

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: badgeColor.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: badgeColor.withValues(alpha: 0.15)),
      ),
      child: Row(
        children: [
          Icon(icon, size: 22, color: badgeColor.withValues(alpha: 0.8)),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name,
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                    color: Color(0xFFE8E8F0),
                  ),
                ),
                if (detail != null)
                  Text(
                    detail!,
                    style: TextStyle(
                      fontSize: 12,
                      color: badgeColor.withValues(alpha: 0.7),
                    ),
                  ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: BoxDecoration(
              color: badgeColor.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(badgeIcon, size: 14, color: badgeColor),
                const SizedBox(width: 4),
                Text(
                  badgeText,
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: badgeColor,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _ErrorCard extends StatelessWidget {
  final String message;
  const _ErrorCard({required this.message});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      margin: const EdgeInsets.only(bottom: 16),
      decoration: BoxDecoration(
        color: Colors.red.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: Colors.red.withValues(alpha: 0.3)),
      ),
      child: Row(
        children: [
          const Icon(Icons.error_outline, color: Colors.red),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              message,
              style: const TextStyle(color: Colors.red, fontSize: 14),
            ),
          ),
        ],
      ),
    );
  }
}
