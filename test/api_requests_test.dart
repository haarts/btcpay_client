import "dart:io";

import 'package:test/test.dart';
import "package:mock_web_server/mock_web_server.dart";

import 'package:btcpay_client/btcpay_client.dart';
import 'package:btcpay_client/key_utils.dart';
import 'package:btcpay_client/exceptions.dart';

MockWebServer server;
Client client;

void main() {
  setUp(() async {
    server = MockWebServer();
    await server.start();

    client = Client(server.url, randomSecp256k1KeyPair());
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

    var response = await client.clientInitiatedPairing();

    expect(
        response,
        allOf([
          contains('api-access-request'),
          contains('abcd'),
        ]));
  });

  test('Throws an exception when remote returns non 200', () async {
    server.enqueue(httpCode: 400, body: '{"error":"some error"}');

    expect(
        client.clientInitiatedPairing(),
        throwsA(predicate((e) =>
            e.message.startsWith("Server returned non 200 status code: 400"))));
  });

  test('Throws an NoPaymentMethodAvailable exception', () async {
    server.enqueue(
        httpCode: 400,
        body: '{"error":"No payment method available for this store\\n"}');

    expect(client.clientInitiatedPairing(),
        throwsA(TypeMatcher<NoPaymentMethodAvailable>()));
  });

  test('Throws an Unauthorized exception', () async {
    server.enqueue(
      httpCode: 401,
    );

    expect(
        client.clientInitiatedPairing(), throwsA(TypeMatcher<Unauthorized>()));
  });

  test('Get a token', () async {
    server.enqueue(
        body:
            '{"data":[{"token":"EM1mSreZ2rkeLM772z5AbHF44ekzHcA3SksFYNesu8yo"}]}');
    var client = Client(server.url, randomSecp256k1KeyPair());

    var response = await client.getToken();

    expect(response, isNotEmpty);
  });

  test('Signs a http request', () async {
    server.enqueue(
        body:
            '{"data":[{"token":"EM1mSreZ2rkeLM772z5AbHF44ekzHcA3SksFYNesu8yo"}]}');
    var client = Client(server.url, randomSecp256k1KeyPair());

    await client.getToken();
    var request = server.takeRequest();

    expect(request.headers['x-signature'], isNotNull);
    expect(request.headers['x-identity'], isNotNull);
  });

  test('Creates an invoice', () async {
    server.enqueue(
        body:
            '{"data":[{"token":"EM1mSreZ2rkeLM772z5AbHF44ekzHcA3SksFYNesu8yo"}]}');
    var cannedResponse =
        await File('test/files/create_invoice_response.json').readAsString();
    server.enqueue(body: cannedResponse);
    var client = Client(server.url, randomSecp256k1KeyPair());

    var response = await client.createInvoice(1.0, "CHF");
    var request = server.takeRequest();

    expect(response, TypeMatcher<Map<String, dynamic>>());
    expect(request.uri.path, '/invoices');
    expect(request.method, 'POST');
  });

  test('Get an invoice', () async {
    var cannedResponse =
        await File('test/files/get_invoice_response.json').readAsString();
    server.enqueue(body: cannedResponse);
    var client = Client(server.url, randomSecp256k1KeyPair());

    await client.getInvoice("abcde");
    var request = server.takeRequest();

    expect(request.uri.path, '/invoices/abcde');
    expect(request.method, 'GET');
  });
}
