import 'dart:async';
import 'dart:core';
import 'dart:io';

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/api.dart";
import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';

void main() async {
  var keyPair = randomSecp256k1KeyPair();
  save('/tmp/d', keyPair.privateKey);

  var client = Client("https://test2-btc-ltc.forkbitpay.ninja/", keyPair);

  String url = await client.clientInitiatedPairing(label());
  print('Visit this url to complete pairing: $url');
}

String label() {
  var now = DateTime.now();

  return 'cli - ${now.day}-${now.month}-${now.year} ${now.hour}:${now.minute}';
}
