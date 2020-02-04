import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/ec_key_generator.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/random/fortuna_random.dart';

final sha256digest = SHA256Digest();
final ecParams = ECCurve_secp256k1();

/// Generates a random secp256k1 key pair.
AsymmetricKeyPair randomSecp256k1KeyPair() {
  var keyParams = ECKeyGeneratorParameters(ecParams);

  var random = FortunaRandom();
  random.seed(KeyParameter(_seed()));

  var generator = ECKeyGenerator();
  generator.init(ParametersWithRandom(keyParams, random));

  return generator.generateKeyPair();
}

/// Returns a serialized form of the private key which can be stored.
/// It might seem odd to have such a trivial method but doing this prevents
/// the user of this library from including a bunch of PointyCastle
/// dependencies.
BigInt serialize(ECPrivateKey privateKey) {
  return privateKey.d;
}

/// Reconstructs a private key and returns a key pair.
AsymmetricKeyPair deserialize(BigInt d) {
  // ignore: omit_local_variable_types
  ECPrivateKey privateKey = ECPrivateKey(d, ecParams);
  // ignore: omit_local_variable_types
  ECPublicKey publicKey = _derivePublicKeyFrom(privateKey);

  return AsymmetricKeyPair(publicKey, privateKey);
}

/// Saves the private key to a file.
Future<void> save(String fileName, ECPrivateKey privateKey) async {
  var file = File(fileName);
  await file.create();
  await file.writeAsString(serialize(privateKey).toString());
}

/// Loads a private key from file and reconstructs the public key.
Future<AsymmetricKeyPair> load(String fileName) async {
  var file = File(fileName);
  var d = await file.readAsString();

  return deserialize(BigInt.parse(d));
}

/// Sign a message.
String sign(String message, ECPrivateKey key) {
  // ignore: omit_local_variable_types
  ECDSASigner signer = _createSigner(key);
  ECSignature signature = signer.generateSignature(utf8.encode(message));

  return _encodeSignature(signature);
}

/// Verify a message.
bool verify(String message, String signature, ECPublicKey key) {
  // ignore: omit_local_variable_types
  ECDSASigner verifier = _createVerifier(key);
  // ignore: omit_local_variable_types
  ECSignature decodedSignature = _decodeSignature(signature);

  return verifier.verifySignature(utf8.encode(message), decodedSignature);
}

ECDSASigner _createVerifier(ECPublicKey key) {
  var forSigning = false;
  var params = PublicKeyParameter(key);
  Mac signerMac = HMac(sha256digest, 64);

  return ECDSASigner(sha256digest, signerMac)..init(forSigning, params);
}

ECDSASigner _createSigner(ECPrivateKey key) {
  var forSigning = true;
  var params = PrivateKeyParameter(key);
  Mac signerMac = HMac(sha256digest, 64);

  return ECDSASigner(sha256digest, signerMac)..init(forSigning, params);
}

ECSignature _decodeSignature(String signature) {
  var parser = ASN1Parser(hex.decoder.convert(signature));
  ASN1Sequence sequence = parser.nextObject();
  ASN1Integer r = sequence.elements[0];
  ASN1Integer s = sequence.elements[1];

  return ECSignature(r.valueAsBigInteger, s.valueAsBigInteger);
}

String _encodeSignature(ECSignature signature) {
  var sequence = ASN1Sequence();
  sequence.add(ASN1Integer(signature.r));
  sequence.add(ASN1Integer(signature.s));

  return hex.encoder.convert(sequence.encodedBytes);
}

ECPublicKey _derivePublicKeyFrom(ECPrivateKey privateKey) {
  return ECPublicKey(ecParams.G * privateKey.d, ecParams);
}

Uint8List _seed() {
  var random = Random.secure();
  var seed = List<int>.generate(32, (_) => random.nextInt(256));

  return Uint8List.fromList(seed);
}
