import "dart:typed_data";
import "dart:math";
import "package:base58check/base58.dart";
import 'package:convert/convert.dart';
import "package:pointycastle/pointycastle.dart";
import "package:pointycastle/export.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/curves/secp256k1.dart";
import "package:pointycastle/key_generators/api.dart";
import "package:pointycastle/key_generators/ec_key_generator.dart";
import "package:pointycastle/random/fortuna_random.dart";

void main() {
  var keyPair = randomSecp256k1KeyPair();
  ECPrivateKey privateKey = keyPair.privateKey;
  print(privateKey.d); // 'd' is a BigInt
}

class Client {
  const String userAgent = 'BTCPay - Dart';

  String uri;
  AsymmetricKeyPair keyPair;
  String clientId;

  const int prefix = 0x0F;
  const int sinType = 0x02;

  static final sha256digest = SHA256Digest();
  static final ripemd160digest = RIPEMD160Digest();

  Client(this.uri, this.keyPair) {
    clientId = _convertToClientId(keyPair.publicKey);
  }

  String _convertToClientId(ECPublicKey publicKey) {
    var versionedDigest = [prefix, sinType];
    var digest =
        ripemd160digest.process(sha256digest.process(publicKey.Q.getEncoded()));
    versionedDigest.addAll(digest);
    var checksum = sha256digest
        .process(sha256digest.process(Uint8List.fromList(versionedDigest)))
        .getRange(0, 4);
    versionedDigest.addAll(checksum);
    return Base58Codec(
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        .encode(versionedDigest);
  }
}

AsymmetricKeyPair<PublicKey, PrivateKey> randomSecp256k1KeyPair() {
  var keyParams = ECKeyGeneratorParameters(ECCurve_secp256k1());

  var random = FortunaRandom();
  random.seed(KeyParameter(_seed()));

  var generator = ECKeyGenerator();
  generator.init(ParametersWithRandom(keyParams, random));

  return generator.generateKeyPair();
}

_generate_sin(ECPublicKey key) {}

Uint8List _seed() {
  var random = Random.secure();
  var seed = List<int>.generate(32, (_) => random.nextInt(256));
  return Uint8List.fromList(seed);
}

// TODO
// Restore the ECPrivateKey from 'd'.
