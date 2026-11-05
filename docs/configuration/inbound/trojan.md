### Structure

```json
{
  "type": "trojan",
  "tag": "trojan-in",

  ... // Listen Fields

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "tls": {},
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "fallback_for_alpn": {
    "http/1.1": {
      "server": "127.0.0.1",
      "server_port": 8081
    }
  },
  "multiplex": {},
  "transport": {}
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

==Required==

Trojan users.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

#### fallback

!!! failure ""

    There is no evidence that GFW detects and blocks Trojan servers based on HTTP responses, and opening the standard http/s port on the server is a much bigger signature.

Fallback server configuration. Disabled if `fallback` and `fallback_for_alpn` are empty.


With a fallback configured, the initial Trojan request-header timeout is 30 seconds
(10 seconds without a fallback). Unauthenticated bytes are replayed to the fallback,
which inherits what is left of that deadline instead of a fresh one: until the client
completes a request head (an empty line, as in HTTP/1, or the HTTP/2 preface), the
fallback's read side ends when the original deadline passes, and its write side stays
open for a response. A probe therefore cannot gain a second full web-header wait by
choosing when to break the key format. Once the head is complete, the fallback's own
timeouts apply, so keep-alive and uploads are unaffected. Ordinary non-Trojan requests
are forwarded immediately once their format rules out authentication. At most 1024
connections per inbound are handed to the fallback at once; further ones are closed.

Both CRLF separators of the request header and of every UDP frame are verified.
Repeated handshake failures are logged once a minute at error level, the rest at
debug level. None of this adds a delay to valid clients or changes the wire format.
External web servers may have different timeout and error behavior; this is not a
guarantee of equivalence to every HTTPS server.

#### fallback_for_alpn

Fallback server configuration for specified ALPN.

If not empty, TLS fallback requests with ALPN not in this table will be rejected.

#### multiplex

See [Multiplex](/configuration/shared/multiplex#inbound) for details.

#### transport

V2Ray Transport configuration, see [V2Ray Transport](/configuration/shared/v2ray-transport/).
