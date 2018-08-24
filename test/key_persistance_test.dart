import 'dart:io';
import 'package:test/test.dart';
import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";

import 'package:btcpay_client/btcpay-client.dart';

void main() {
  test('Saves key to disk', () async {
    var keyPair = randomSecp256k1KeyPair();
    await save(keyPair.privateKey);

    var file = File('/tmp/d');
    expect(await file.exists(), true);
  });

  test('Loads key from disk', () async {
    ECPrivateKey privateKey = randomSecp256k1KeyPair().privateKey;
    await save(privateKey);

    var key = await load();
    expect(key.d, equals(privateKey.d));
  });
}
