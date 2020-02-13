import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';

void main(List<String> args) async {
  var client =
      Client('https://testnet.demo.btcpayserver.org/', await load('/tmp/d'));
  print(await client.getInvoice(args[0]));
}
