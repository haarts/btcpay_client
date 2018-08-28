import "dart:io";
import "dart:core";
import "dart:async";
import "dart:convert";
import "dart:typed_data";

import 'package:convert/convert.dart';
import "package:base58check/base58.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/digests/sha256.dart";
import "package:pointycastle/digests/ripemd160.dart";

import "key_utils.dart";

class Client {
  const String userAgent = '{BTC|Bit}Pay - Dart';

  Uri url;
  AsymmetricKeyPair keyPair;
  HttpClient httpClient;

  const String tokenPath = 'tokens';
  const String apiAccessRequestPath = 'api-access-request';
  const String invoicesPath = 'invoices';

  /// clientId aka SIN
  String clientId;

  const String alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const int prefix = 0x0F;
  const int sinType = 0x02;


  static final ripemd160digest = RIPEMD160Digest();
  static final sha256digest = SHA256Digest();

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

  String getToken() async {
    // Annoyingly the Dart compiler doesn't correctly infer the sub type.
    ECPublicKey publicKey = keyPair.publicKey;
    var request = await httpClient.getUrl(url.replace(path: tokenPath));
    request.headers
        .set('X-Signature', sign(request.uri.toString(), keyPair.privateKey));
    request.headers
        .set('X-Identity', hex.encoder.convert(publicKey.Q.getEncoded(false)));
    var response = await request.close();

    return await response.transform(utf8.decoder).join();
  }

  String createInvoice(double price, String currency) async {
    // TODO
    await httpClient
        .postUrl(url.replace(path: invoicesPath))
        .then((HttpClientRequest request) {
      String body = '{}';
      request.headers.set('X-Signature',
          sign(request.uri.toString() + body, keyPair.privateKey));
      request.headers.set('X-Identity', clientId);
      request.write(body);
      return request.close();
    }).then((HttpClientResponse response) {
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

