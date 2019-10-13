import 'dart:io';

import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';

void main(List<String> args) async {
  if (args.length != 2) {
    print('Please pass an amount and a currency.');
    exit(1);
  }

  var client =
      Client("https://testnet.demo.btcpayserver.org/", await load('/tmp/d'));
  print(await client.createInvoice(double.parse(args[0]), args[1]));
}
