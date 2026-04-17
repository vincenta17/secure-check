import 'package:flutter_test/flutter_test.dart';
import 'package:secure_check/main.dart';

void main() {
  testWidgets('App renders without crashing', (WidgetTester tester) async {
    await tester.pumpWidget(const SecureCheckApp());
    expect(find.text('Secure Check'), findsOneWidget);
  });
}
