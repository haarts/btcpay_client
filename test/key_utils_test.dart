import 'dart:io';
import 'package:test/test.dart';
import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";

import 'package:btcpay_client/btcpay-client.dart';
import 'package:btcpay_client/key_utils.dart';

void main() {
  test('Saves key to disk', () async {
    var keyPair = randomSecp256k1KeyPair();
    await save('/tmp/d', keyPair.privateKey);

    var file = File('/tmp/d');
    expect(await file.exists(), true);
  });

  test('Loads key from disk', () async {
    AsymmetricKeyPair keyPair = randomSecp256k1KeyPair();
    ECPrivateKey privateKey = keyPair.privateKey;
    ECPublicKey publicKey = keyPair.publicKey;

    await save('/tmp/d', privateKey);

    AsymmetricKeyPair loadedKeyPair = await load('/tmp/d');

    ECPrivateKey loadedPrivateKey = loadedKeyPair.privateKey;
    expect(loadedPrivateKey.d, equals(privateKey.d));

    ECPublicKey loadedPublicKey = loadedKeyPair.publicKey;
    expect(loadedPublicKey.Q, equals(publicKey.Q));
  });

  test('Sign message', () {
    var message = "random message";
    var keyPair = randomSecp256k1KeyPair();
    var signature = sign(message, keyPair.privateKey);

    expect(verify(message, signature, keyPair.publicKey), equals(true));
  });
}
