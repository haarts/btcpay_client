import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';

void main(List<String> args) async {
  var client =
      Client("https://btcpay-ch-1.feathercoin.ch/", await load('/tmp/d'));
  print(await client.createInvoice(double.parse(args[0]), args[1]));
}
