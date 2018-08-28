import "dart:convert";
import 'package:test/test.dart';
import "package:mock_web_server/mock_web_server.dart";
import "package:pointycastle/api.dart";

import 'package:btcpay_client/btcpay-client.dart';
import 'package:btcpay_client/key_utils.dart';

MockWebServer server;

void main() {

  setUp(() {
    server = MockWebServer();
    server.start();
  });

  tearDown(() {
    server.shutdown();
  });

  test('Client stores base URL', () {
    var url = "https://irrelevant";
    var client = Client(url, randomSecp256k1KeyPair());

    expect(client.url.toString(), equals(url));
  });

  test('Returns an URL to complete client side initiated pairing', () async {
    server.enqueue(body: '{"data": [{"pairingCode": "abcd"}]}');

    var client = Client(server.url, randomSecp256k1KeyPair());
    var response = await client.clientInitiatedPairing();
    
    expect(response, allOf([
      contains('api-access-request'),
      contains('abcd'),
     ]));
  });

  test('Get a token', () async {
    server.enqueue(body: '{"data":[{"pos":"EM1mSreZ2rkeLM772z5AbHF44ekzHcA3SksFYNesu8yo"}]}');
    var client = Client(server.url, randomSecp256k1KeyPair());

    var response = await client.getToken();

    expect(response, isNotEmpty);
  });

  test('Signs a http request', () async {
    server.enqueue(body: '{"data":[{"pos":"EM1mSreZ2rkeLM772z5AbHF44ekzHcA3SksFYNesu8yo"}]}');
    var client = Client(server.url, randomSecp256k1KeyPair());

    var response = await client.getToken();

		var request = server.takeRequest();

    expect(request.headers['x-signature'], isNotNull);
    expect(request.headers['x-identity'], isNotNull);
  });
}
