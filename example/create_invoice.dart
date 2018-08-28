import 'dart:async';
import 'dart:io';

import 'package:btcpay_client/btcpay-client.dart';
import 'package:btcpay_client/key_utils.dart';

void main() async {
  var client =
      Client("https://test2-btc-ltc.forkbitpay.ninja/", await load('/tmp/d'));
  print(await client.getToken());
}

