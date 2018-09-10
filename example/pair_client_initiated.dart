import 'dart:core';

import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';

void main() async {
  var keyPair = randomSecp256k1KeyPair();
  save('/tmp/d', keyPair.privateKey);

  var client = Client("https://btcpay-ch-1.feathercoin.ch", keyPair);

  String url = await client.clientInitiatedPairing(label());
  print('Visit this url to complete pairing: $url');
}

String label() {
  var now = DateTime.now();

  return 'cli - ${now.day}-${now.month}-${now.year} ${now.hour}:${now.minute}';
}
