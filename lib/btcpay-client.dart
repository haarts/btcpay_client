import "dart:typed_data";
import "dart:core";
import "dart:convert";
import "dart:math";
import "dart:io";
import "dart:async";

import "package:base58check/base58.dart";
import 'package:convert/convert.dart';
import 'package:asn1lib/asn1lib.dart';
import "package:pointycastle/pointycastle.dart";
import "package:pointycastle/export.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/curves/secp256k1.dart";
import "package:pointycastle/key_generators/api.dart";
import "package:pointycastle/key_generators/ec_key_generator.dart";
import "package:pointycastle/random/fortuna_random.dart";

class Client {
  const String userAgent = '{BTC|Bit}Pay - Dart';

  Uri url;
  AsymmetricKeyPair keyPair;
  HttpClient httpClient;

  const String tokenPath = 'tokens';
  const String apiAccessRequestPath = 'api-access-request';
  const String invoicesPath = 'invoices';

  // clientId aka SIN
  String clientId;

  const String alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const int prefix = 0x0F;
  const int sinType = 0x02;

  static final sha256digest = SHA256Digest();
  static final ripemd160digest = RIPEMD160Digest();

  Client(String url, this.keyPair) {
    clientId = _convertToClientId(keyPair.publicKey);
    httpClient = HttpClient();
    this.url = Uri.parse(url);
  }

  /// Returns a URL to which the user must go to approve the pairing.
  String clientInitiatedPairing() async {
    // When I grow up I want to make this eye sore pretty.
    var request = await _requestPairingCode();
    var response = await request;
    String pairingCode;
    await response.transform(utf8.decoder).listen((contents) {
      pairingCode = json.decode(contents)['data'][0]['pairingCode'];
    });

    return url.replace(
      path: apiAccessRequestPath,
      queryParameters: {'pairingCode': pairingCode},
    ).toString();
  }

  String invoice(double price, String currency) async {
    await httpClient
        .postUrl(url.replace(path: invoicesPath))
        .then((HttpClientRequest request) {
      String body = '{}';
      request.headers.set('X-Signature',
          sign(request.uri.toString() + body, keyPair.privateKey));
      request.headers.set('X-Identity', clientId);
      request.write(body);
      print(request.headers);
      print(request.uri);
      return request.close();
    }).then((HttpClientResponse response) {
      print(response.statusCode);
      response.transform(utf8.decoder).listen((contents) {
                                                    print(contents);
      });
    });

    return "";
  }

  Future<HttpClientResponse> _requestPairingCode() async {
    return await httpClient
        .postUrl(url.replace(path: tokenPath))
        .then((HttpClientRequest request) {
      request.headers.contentType = ContentType.json;
      request.write("{'id':'$clientId', 'facade': 'pos'}");
      return request.close();
    });
  }

  /// Converts a public key to a SIN type identifier as per https://en.bitcoin.it/wiki/Identity_protocol_v1.
  String _convertToClientId(ECPublicKey publicKey) {
    var versionedDigest = [prefix, sinType];
    var digest =
        ripemd160digest.process(sha256digest.process(publicKey.Q.getEncoded()));
    versionedDigest.addAll(digest);
    var checksum = sha256digest
        .process(sha256digest.process(Uint8List.fromList(versionedDigest)))
        .getRange(0, 4);
    versionedDigest.addAll(checksum);
    return Base58Codec(alphabet).encode(versionedDigest);
  }
}

String sign(String message, ECPrivateKey key) {
  ECDSASigner signer = _createSigner(key);
  ECSignature signature = signer.generateSignature(utf8.encode(message));

  return _encodeSignature(signature);
}

bool verify(String message, String signature, ECPublicKey key) {
  ECDSASigner verifier = _createVerifier(key);
  ECSignature decodedSignature = _decodeSignature(signature);

  return verifier.verifySignature(utf8.encode(message), decodedSignature);
}

ECDSASigner _createVerifier(ECPublicKey key) {
  var forSigning = false;
  var params = PublicKeyParameter(key);
  Mac signerMac = HMac(SHA256Digest(), 64);

  return ECDSASigner(null, signerMac)..init(forSigning, params);
}

ECDSASigner _createSigner(ECPrivateKey key) {
  var forSigning = true;
  var params = PrivateKeyParameter(key);
  Mac signerMac = HMac(SHA256Digest(), 64);

  return ECDSASigner(null, signerMac)..init(forSigning, params);
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

ECPublicKey derivePublicKeyFrom(ECPrivateKey privateKey) {
  var ecParams = ECCurve_secp256k1();
  return ECPublicKey(ecParams.G * privateKey.d, ecParams);
}

AsymmetricKeyPair<PublicKey, PrivateKey> randomSecp256k1KeyPair() {
  var keyParams = ECKeyGeneratorParameters(ECCurve_secp256k1());

  var random = FortunaRandom();
  random.seed(KeyParameter(_seed()));

  var generator = ECKeyGenerator();
  generator.init(ParametersWithRandom(keyParams, random));

  return generator.generateKeyPair();
}

Uint8List _seed() {
  var random = Random.secure();
  var seed = List<int>.generate(32, (_) => random.nextInt(256));
  return Uint8List.fromList(seed);
}

void save(ECPrivateKey privateKey) async {
  var file = File('/tmp/d');
  await file.create();
  await file.writeAsString(privateKey.d.toString());
}

ECPrivateKey load() async {
  var file = File('/tmp/d');
  var d = await file.readAsString();
  return ECPrivateKey(BigInt.parse(d), ECCurve_secp256k1());
}

// TODO
// Restore the ECPrivateKey from 'd'.
