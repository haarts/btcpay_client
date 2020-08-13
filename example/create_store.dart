import 'package:btcpay_client/btcpay_client.dart';

//ignore_for_file: avoid_print

Future<void> main(List<String> args) async {
  var client = Client.fromUserAuthenticationToken(
      'https://testnet.demo.btcpayserver.org/', 'my-user-token');
  print(await client.createStore('store-from-unit-test'));
}
