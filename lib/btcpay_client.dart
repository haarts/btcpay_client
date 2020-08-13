import 'dart:async';
import 'dart:convert';
import 'dart:core';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:base58check/base58.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/ripemd160.dart';

import 'exceptions.dart';
import 'key_utils.dart';

class Client {
  /// Create a client based on a server URL and a `AsymmetricKeyPair`.
  Client(String url, this.keyPair) {
    clientId = _convertToClientId(keyPair.publicKey);
    identity = hex.encoder
        .convert((keyPair.publicKey as ECPublicKey).Q.getEncoded(true));
    _httpClient = HttpClient();
    this.url = Uri.parse(url);
  }

  Client.fromUserAuthenticationToken(String url, this.userAuthenticationToken) {
    _httpClient = HttpClient();
    this.url = Uri.parse(url);
  }

  /// Create a client based on a server URL and a `BigInt` representation of a
  /// private key.
  Client.fromBarePrivateKey(String url, BigInt privateKey)
      : this(url, deserialize(privateKey));

  /// Used to send an appropriate User-Agent header with the HTTP requests.
  static const String userAgent = '{BTC|Bit}Pay - Dart';

  /// The URL of the BTCPay server.
  Uri url;

  /// The key pair used to sign requests.
  AsymmetricKeyPair keyPair;

  /// This token is required to make a successful request.
  String authorizationToken;

  // This token is set on the user level and e.g. used to create new stores
  String userAuthenticationToken;

  HttpClient _httpClient;

  static const String tokenPath = 'tokens';
  static const String apiAccessRequestPath = 'api-access-request';
  static const String invoicesPath = 'invoices';
  static const String storePath = 'api/v1/stores';

  /// aka SIN. This is generated from the public key.
  String clientId;

  /// Derived from the [clientId] and used for the 'X-Identity' header.
  String identity;

  static const String _alphabet =
      '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  /// As per https://en.bitcoin.it/wiki/Identity_protocol_v1
  static const int _prefix = 0x0F;

  /// Bitpay uses ephemeral SIN's. As per https://en.bitcoin.it/wiki/Identity_protocol_v1
  static const int _sinType = 0x02;

  static final _ripemd160digest = RIPEMD160Digest();
  static final _sha256digest = SHA256Digest();

  /// Pairs a client based on a pairing code provided by the server
  Future<Map<String, dynamic>> serverInitiatedPairing(String pairingCode,
      [String label]) async {
    var request = await _pair(pairingCode: pairingCode, label: label);
    var response = await _doRequest(request);

    return response;
  }

  /// Returns a URL to which the user must go to approve the pairing.
  Future<String> clientInitiatedPairing([String label]) async {
    var request = await _pair(label: label);
    var response = await _doRequest(request);
    String pairingCode = response['data'][0]['pairingCode'];

    return url.replace(
      path: apiAccessRequestPath,
      queryParameters: {'pairingCode': pairingCode},
    ).toString();
  }

  Future<String> createStore(String name) async {
    var request =
        await _httpClient.postUrl(url.replace(path: storePath)).then((request) {
      var params = {
        'Name': name,
      };

      // Creating a store is done using the Greenfield authentication scheme
      request.headers.set('authorization', 'token $userAuthenticationToken');
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(params));

      return request;
    });

    var body = await _doRequest(request);

    return body['id'];
  }

  /// Creates an invoice on the remote.
  Future<Map<String, dynamic>> createInvoice(
      double price, String currency) async {
    authorizationToken ??= await getToken();

    var request = await _httpClient
        .postUrl(url.replace(path: invoicesPath))
        .then((request) {
      var params = {
        'token': authorizationToken,
        'id': clientId,
        'price': price,
        'currency': currency,
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
    var request = await _httpClient
        .getUrl(url.replace(path: '$invoicesPath/$id'))
        .then((request) {
      request.headers.set('X-Identity', identity);
      request.headers.set(
        'X-Signature',
        sign(request.uri.toString(), keyPair.privateKey),
      );
      request.headers.contentType = ContentType.json;

      return request;
    });

    var response = await _doRequest(request);

    return response;
  }

  /// Returns a token which is required to create a invoice.
  Future<String> getToken() async {
    var request = await _httpClient.postUrl(url.replace(path: tokenPath));
    var payload = jsonEncode({
      'id': clientId,
      // facade is ignored, always returns merchant
      'facade': 'pos',
    });
    request.headers.contentType = ContentType.json;
    request.headers.set('X-Accept-Version', '2.0.0');
    request.write(payload);
    var body = await _doRequest(request);
    if (body['data'].isEmpty) {
      return '';
    }
    return body['data'][0]['token'];
  }

  Future<Map<String, dynamic>> _doRequest(HttpClientRequest request) async {
    var response = await request.close();
    if (response.statusCode == HttpStatus.unauthorized) {
      throw Unauthorized(request.uri.toString(), request.method);
    }

    // We assume the server ALWAYS returns a nice UTF8 encoded JSON body.
    var body = await utf8.decodeStream(response);
    Map<String, dynamic> json = jsonDecode(body);
    if (response.statusCode == HttpStatus.ok) {
      return json;
    }

    if (NoPaymentMethodAvailable.isDefinedBy(json)) {
      throw NoPaymentMethodAvailable();
    }

    // At some point each and every exception thrown by the backend should have
    // its own custom Exception.
    throw Exception(
        'Server returned non 200 status code: ${response.statusCode} - ${request.method} - ${request.uri} - $body');
  }

  Future<HttpClientRequest> _pair({String label, String pairingCode}) async {
    var params = {
      'id': clientId,
      'facade': 'pos',
    };

    if (pairingCode != null) {
      params['pairingCode'] = pairingCode;
    }

    if (label != null) {
      params['label'] = label;
    }

    return _httpClient.postUrl(url.replace(path: tokenPath)).then((request) {
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(params));
      return request;
    });
  }

  /// Converts a public key to a SIN type identifier as per https://en.bitcoin.it/wiki/Identity_protocol_v1.
  String _convertToClientId(ECPublicKey publicKey) {
    var versionedDigest = [_prefix, _sinType];
    var digest = _ripemd160digest
        .process(_sha256digest.process(publicKey.Q.getEncoded()));
    versionedDigest.addAll(digest);
    var checksum = _sha256digest
        .process(_sha256digest.process(Uint8List.fromList(versionedDigest)))
        .getRange(0, 4);
    versionedDigest.addAll(checksum);
    return Base58Codec(_alphabet).encode(versionedDigest);
  }

  @override
  String toString() => 'Client(url: $url)';
}
