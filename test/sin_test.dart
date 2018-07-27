import 'package:test/test.dart';
import 'package:convert/convert.dart';
import "package:pointycastle/ecc/curves/secp256k1.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/api.dart";

import 'package:btcpay_client/btcpay-client.dart';

void main() {
  test('Generate SIN from EC PrivateKey', () {
    String hexEncodedPublicKey =
        '038d970d6ba29dcfa190c177140fd889fadd6d2590b1ee1a6a06e255dbf22b4017';
    String clientId = 'TeyN4LPrXiG5t2yuSamKqP3ynVk3F52iHrX';

    var ecParams = ECCurve_secp256k1();
    List<int> decodedPublicKey = hex.decoder.convert(hexEncodedPublicKey);
    var publicKey =
        ECPublicKey(ecParams.curve.decodePoint(decodedPublicKey), ecParams);
    var client = Client("irrelevant", AsymmetricKeyPair(publicKey, null));
    expect(client.clientId, equals(clientId));
  });
}
