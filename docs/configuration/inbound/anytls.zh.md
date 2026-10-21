---
icon: material/new-box
---

!!! question "自 sing-box 1.12.0 起"

### 结构

```json
{
  "type": "anytls",
  "tag": "anytls-in",

  ... // 监听字段

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

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### users

==必填==

AnyTLS 用户。

#### padding_scheme

AnyTLS 填充方案行数组。

默认填充方案:

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

为空时使用默认填充方案；启用 `traffic_shaping` 时改为每个入站生成一次的可变长度方案。

#### traffic_shaping

使用标准 AnyTLS 填充帧的服务端下行整形，客户端无需新增配置或协议扩展。

默认禁用，保持原有发送方式。字段为零时使用上方所示默认值。`max_padding_bytes` 是每个会话的下行填充预算（包含帧头），不限制客户端上传填充。

长度指向 TLS 连接的写入，不代表 IP 包或确定的 TLS record 长度。

#### handshake_timeout

读取认证及其填充的时间限制，默认 `10s`。

认证失败、提前关闭或超时的请求会连同已收到的全部字节交给回落服务器。

#### tls

TLS 配置, 参阅 [TLS](/zh/configuration/shared/tls/#入站)。

#### fallback

回落服务器配置。如果 `fallback` 和 `fallback_for_alpn` 为空，则禁用回落。

#### fallback_for_alpn

为 ALPN 指定回落服务器配置。

如果不为空，ALPN 不在此列表中的 TLS 回落请求将被拒绝。
