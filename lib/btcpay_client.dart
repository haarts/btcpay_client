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
  String authorizationToken;

  const String tokenPath = 'tokens';
  const String apiAccessRequestPath = 'api-access-request';
  const String invoicesPath = 'invoices';

  /// clientId aka SIN
  String clientId;
  String identity;

  const String alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const int prefix = 0x0F;
  const int sinType = 0x02;

  static final ripemd160digest = RIPEMD160Digest();
  static final sha256digest = SHA256Digest();

  Client(String url, this.keyPair) {
    clientId = _convertToClientId(keyPair.publicKey);
    identity = hex.encoder
        .convert((keyPair.publicKey as ECPublicKey).Q.getEncoded(true));
    httpClient = HttpClient();
    this.url = Uri.parse(url);
  }

  Client.fromBarePrivateKey(String url, BigInt privateKey)
      : this(url, deserialize(privateKey));

  /// Pairs a client based on a pairing code provided by the server
  Future<Map<String, dynamic>> serverInitiatedPairing(
      String pairingCode) async {
    var request = await _pair(pairingCode);
    var response = await _doRequest(request);

    return response;
  }

  /// Returns a URL to which the user must go to approve the pairing.
  Future<String> clientInitiatedPairing([String label]) async {
    var request = await _pair(label);
    var response = await _doRequest(request);
    String pairingCode = response['data'][0]['pairingCode'];

    return url.replace(
      path: apiAccessRequestPath,
      queryParameters: {'pairingCode': pairingCode},
    ).toString();
  }

  /// Creates an invoice on the remote.
  Future<Map<String, dynamic>> createInvoice(
      double price, String currency) async {
    authorizationToken ??= await getToken();

    HttpClientRequest request = await httpClient
        .postUrl(url.replace(path: invoicesPath))
        .then((HttpClientRequest request) {
      Map<String, dynamic> params = {
        "token": authorizationToken,
        "id": clientId,
        "price": price,
        "currency": currency,
      };
      request.headers.set(
        'X-Signature',
        sign(request.uri.toString() + jsonEncode(params), keyPair.privateKey),
      );
      request.headers.set('X-Identity', identity);
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(params));

      return request;
    });

    var body = await _doRequest(request);

    return body;
  }

  Future<Map<String, dynamic>> getInvoice(String id) async {
    var request = await httpClient
        .getUrl(url.replace(path: '$invoicesPath/$id'))
        .then((HttpClientRequest request) {
      request.headers.contentType = ContentType.json;

      return request;
    });

    var response = await _doRequest(request);

    return response;
  }

  /// Returns a token which is required to create a invoice.
  Future<String> getToken() async {
    // Annoyingly the Dart compiler doesn't correctly infer the sub type.
    ECPublicKey publicKey = keyPair.publicKey;
    var request = await httpClient.getUrl(url.replace(path: tokenPath));
    request.headers
        .set('X-Signature', sign(request.uri.toString(), keyPair.privateKey));
    request.headers.set('X-Identity', identity);

    var body = await _doRequest(request);

    if (body["data"].isEmpty) {
      return "";
    }
    return body["data"][0]["pos"];
  }

  Future<Map<String, dynamic>> _doRequest(HttpClientRequest request) async {
    HttpClientResponse response = await request.close();

    if (response.statusCode != HttpStatus.ok) {
      throw Exception(
          "Server returned non 200 status code: ${response.statusCode} - ${request.method} - ${request.uri}");
    }

    String json = await response.transform(utf8.decoder).join();

    return jsonDecode(json);
  }

  Future<HttpClientRequest> _pair([String label, String pairingCode]) async {
    Map<String, String> params = {
      'id': clientId,
      'facade': 'pos',
    };

    if (pairingCode != null) {
      params['pairingCode'] = pairingCode;
    }

    if (label != null) {
      params['label'] = label;
    }

    return await httpClient
        .postUrl(url.replace(path: tokenPath))
        .then((HttpClientRequest request) {
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(params));
      return request;
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

  @override
  String toString() => "Client(url: $url)";
}
