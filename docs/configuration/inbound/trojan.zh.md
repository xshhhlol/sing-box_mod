### 结构

```json
{
  "type": "trojan",
  "tag": "trojan-in",

  ... // 监听字段

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

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### users

==必填==

Trojan 用户。

#### tls

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#入站)。

#### fallback

!!! failure ""

    没有证据表明 GFW 基于 HTTP 响应检测并阻止 Trojan 服务器，并且在服务器上打开标准 http/s 端口是一个更大的特征。

回退服务器配置。如果 `fallback` 和 `fallback_for_alpn` 为空，则禁用回退。


配置回落时，Trojan 初始请求头期限为 30 秒；无回落时仍为 10 秒。
未认证数据回放给回落服务时，回落沿用剩余期限，不重新计时：客户端发完请求头
（HTTP/1 的空行或 HTTP/2 前言）之前，原期限一到就结束读取方向，保留响应写入方向。
因此探测无论何时打破密钥格式，都拿不到第二轮完整的网站请求头等待。请求头完整后由
回落服务自己的超时接管，不影响长连接和上传。普通非 Trojan 请求在格式排除认证后立即转交。
每个入站同时转交给回落的连接最多 1024 个，超出的直接关闭。

请求头和每个 UDP 帧中的 CRLF 分隔符都会校验。重复的握手失败每分钟只按 error 级别记录一次，
其余按 debug 级别记录。以上都不会给合法客户端添加等待，也不改变协议格式。
外部网站的超时和错误行为可能不同，这不保证与任意 HTTPS 服务器完全一致。

#### fallback_for_alpn

为 ALPN 指定回退服务器配置。

如果不为空，ALPN 不在此列表中的 TLS 回退请求将被拒绝。

#### multiplex

参阅 [多路复用](/zh/configuration/shared/multiplex#入站)。

#### transport

V2Ray 传输配置，参阅 [V2Ray 传输层](/zh/configuration/shared/v2ray-transport/)。