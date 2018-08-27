import 'dart:async';
import 'dart:io';

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/api.dart";
import 'package:btcpay_client/btcpay-client.dart';

void main() async {
  var client =
      Client("https://test2-btc-ltc.forkbitpay.ninja/", await loadKey());
  print(await client.getToken());
}

AsymmetricKeyPair loadKey() async {
  ECPrivateKey privateKey = await load('/tmp/d');
  ECPublicKey publicKey = derivePublicKeyFrom(privateKey);
  return AsymmetricKeyPair(publicKey, privateKey);
}
