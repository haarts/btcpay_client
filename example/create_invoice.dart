import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';

void main(List<String> args) async {
  var client =
      Client("https://test2-btc-ltc.forkbitpay.ninja/", await load('/tmp/d'));
  print(await client.createInvoice(double.parse(args[0]), args[1]));
}
