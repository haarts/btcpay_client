class Unauthorized implements Exception {
  const Unauthorized(this.url, this.method);

  static const String _message = 'Access denied';

  final String url;
  final String method;

  @override
  String toString() {
    return '$_message - $method $url';
  }
}

class NoPaymentMethodAvailable implements Exception {
  const NoPaymentMethodAvailable();

  static const String _message = 'No payment method available for this store\n';

  static bool isDefinedBy(Map<String, dynamic> body) {
    if (!body.containsKey('error')) {
      return false;
    }

    return body['error'].startsWith(_message);
  }

  @override
  String toString() {
    return _message;
  }
}
