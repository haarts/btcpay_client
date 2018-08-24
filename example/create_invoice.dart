import 'dart:async';
import 'dart:io';

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/api.dart";
import 'package:btcpay_client/btcpay-client.dart';

void main() async {
  ECPrivateKey privateKey = await load();
  ECPublicKey publicKey = derivePublicKeyFrom(privateKey);

  var keyPair = AsymmetricKeyPair(publicKey, privateKey);
	var client = Client("https://test2-btc-ltc.forkbitpay.ninja/", keyPair);

	String url = await client.clientInitiatedPairing();
	print(url);
	stdin.readLineSync();

	client.invoice(1.0, 'CHF');
}
