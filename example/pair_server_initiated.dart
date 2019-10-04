import 'dart:io';

import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';

void main(List<String> args) async {
  if (args.length != 1) {
    print('Please pass a server side generated pairing code.');
    exit(1);
  }

  var keyPair = randomSecp256k1KeyPair();
  await save('/tmp/d', keyPair.privateKey);

  var client = Client("https://mainnet.demo.btcpayserver.org/", keyPair);

  var response = await client.serverInitiatedPairing(args[0]);
  print(response);
}
