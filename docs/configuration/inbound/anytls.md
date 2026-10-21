---
icon: material/new-box
---

!!! question "Since sing-box 1.12.0"

### Structure

```json
{
  "type": "anytls",
  "tag": "anytls-in",

  ... // Listen Fields

  "users": [
    {
      "name": "sekai",
      "password": "8JCsPssfgS8tiRwiMlhARg=="
    }
  ],
  "padding_scheme": [],
  "traffic_shaping": {
    "enabled": false,
    "min_record_size": 256,
    "max_record_size": 1400,
    "min_records": 8,
    "max_records": 16,
    "max_padding_bytes": 16384
  },
  "handshake_timeout": "10s",
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
  }
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

==Required==

AnyTLS users.

#### padding_scheme

AnyTLS padding scheme line array.

Default padding scheme:

```json
[
  "stop=8",
  "0=30-30",
  "1=100-400",
  "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
  "3=9-9,500-1000",
  "4=500-1000",
  "5=500-1000",
  "6=500-1000",
  "7=500-1000"
]
```

If empty, the default padding scheme is used, or a variable-length scheme generated once per inbound when `traffic_shaping` is enabled.

#### traffic_shaping

Server-side downlink shaping using standard AnyTLS padding frames. No client option or protocol extension is required.

Disabled by default, which keeps the legacy sender. Zero fields use the defaults shown above. `max_padding_bytes` is the downlink padding budget per session, including frame headers; it does not limit client upload padding.

Record sizes describe writes to the TLS connection, not IP packets or guaranteed TLS record sizes.

#### handshake_timeout

Time limit for reading the authentication and its padding. `10s` is used by default.

Requests that fail authentication, close early or time out are passed with all received bytes to the fallback server.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).

#### fallback

Fallback server configuration. Disabled if `fallback` and `fallback_for_alpn` are empty.

#### fallback_for_alpn

Fallback server configuration for specified ALPN.

If not empty, TLS fallback requests with ALPN not in this table will be rejected.
