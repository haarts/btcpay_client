import 'dart:io';

import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';

//ignore_for_file: avoid_print

Future<void> main(List<String> args) async {
  if (args.length != 2) {
    print('Please pass a server side generated pairing code and a label.');
    exit(1);
  }

  var keyPair = randomSecp256k1KeyPair();
  await save('/tmp/d', keyPair.privateKey);

  var client = Client('https://testnet.demo.btcpayserver.org/', keyPair);

  print(await client.serverInitiatedPairing(args[0], args[1]));
}
