# TLS协议栈测试框架配置说明

本测试框架通过JSON配置文件来驱动TLS协议栈的测试，支持多种TLS协议实现（包括HitLS、OpenSSL、MbedTLS、BoringSSL、RustTLS等）。JSON配置文件中的各个配置项与TLS协议栈的功能模块有着明确的对应关系。

---

## 配置项说明

### `socket` : 底层链路配置
配置TCP/UDP等底层传输链路的参数，对应协议栈的传输层和网络层接口。

- `host`: 可配置`server`或者`client`，指定本端角色
  - 协议栈关系：决定协议栈是作为服务端监听连接还是作为客户端主动发起连接
- `transport_type`: 配置底层链路类型，可配置`tcp` `udp` `sctp` `fakesctp`
  - 协议栈关系：决定协议栈使用的传输协议，TCP对应TLS，UDP对应DTLS
- `server_ip`: 服务端ip地址
  - 协议栈关系：用于建立TCP/UDP连接的目标地址
- `server_port`: 服务端端口
  - 协议栈关系：用于建立TCP/UDP连接的目标端口

### `sslCtx` : SSL上下文命名配置
`sslCtx`命名数组，元素类型为字符串，代表一个命名`sslCtx`（SSL上下文对象）。

- `default_config`: `ctx` 示例名称，其详细配置必须在顶层进行配置
  - 协议栈关系：SSL上下文是协议栈的核心配置对象，包含协议版本、密码套件、证书验证策略等全局配置

### `ssl` : SSL连接命名配置
`ssl` 命名数组，元素类型为字符串，代表一个命名`ssl`（SSL连接对象）。

- `default_ssl`: `ssl` 示例名称，其详细配置必须在顶层进行配置
  - 协议栈关系：SSL连接对象代表一个具体的TLS连接，从SSL上下文继承配置，并维护连接状态

### `cert` : 证书配置数组
可承载多个证书配置，每个元素为json对象，对应协议栈的证书管理模块。

- `name`: 证书命名，用于配置时引用
  - 协议栈关系：证书的标识符，用于在SSL上下文中引用该证书
- `root`: 根证书路径，可配置相对路径，或者绝对路径
  - 协议栈关系：用于验证对端证书链的根CA证书，用于证书链验证
- `chain`: 中间证书，可配置相对路径，或者绝对路径
  - 协议栈关系：用于构建完整的证书链，连接终端证书和根证书
- `dev`: 终端证书，可配置相对路径，或者绝对路径
  - 协议栈关系：本端使用的实体证书，用于身份认证和密钥交换
- `key`: 私钥，可配置相对路径，或者绝对路径
  - 协议栈关系：与终端证书对应的私钥，用于签名和密钥交换
- `enc_cert`: 国密加密证书，可配置相对路径，或者绝对路径
  - 协议栈关系：TLCP协议中使用的加密证书，用于密钥交换
- `enc_key`: 国密加密证书的私钥，可配置相对路径，或者绝对路径
  - 协议栈关系：TLCP协议中加密证书对应的私钥
- `crl`: 证书吊销列表，可配置相对路径，或者绝对路径
  - 协议栈关系：用于检查证书是否已被吊销

### `session` : 用户定义的session命名配置
配置用户定义的session命名数组，对应协议栈的会话管理模块。

- 协议栈关系：用于预定义会话参数，支持外部PSK（预共享密钥）配置，用于会话恢复

### `default_sess` : Session详细配置
引用于 `session` 配置项的元素，对该`session`进行详细配置。

- `version`: 最小版本
  - 协议栈关系：指定会话支持的最低TLS协议版本
- `max_version`: 最大版本，可省略，若未指定则其值与version相同
  - 协议栈关系：指定会话支持的最高TLS协议版本
- `cipher_suite`: 算法套
  - 协议栈关系：指定会话使用的加密算法套件，用于PSK会话恢复时的协商
- `secret`: session中的主密钥(PSK)
  - 协议栈关系：预共享密钥，用于PSK握手模式或会话恢复
- `ticket`: session关联的ticket，tls13 psk扩展中的identity
  - 协议栈关系：会话票据，用于TLS 1.3的会话恢复
- `time_out`: 配置session的超时时间，数字类型
  - 协议栈关系：会话的有效期，超时后需要重新握手

### `default_ssl` : SSL连接详细配置
引用于 `ssl` 配置项的元素，对该`ssl`进行详细配置。

- `from`: 指示该`ssl`引用哪个`ctx`来创建
  - 协议栈关系：SSL连接从指定的SSL上下文继承配置，建立父子关系
- `mtu`: dtls配置mtu，数字类型
  - 协议栈关系：DTLS协议的最大传输单元，影响分片和重传策略
- `dtls_timeout`: dtls配置用户定义超时回调，超时基数 单位s 数字类型
  - 协议栈关系：DTLS协议的超时重传参数，影响可靠性和性能
- `hostname`: 配置客户端的sni，字符串类型；例："hostname" : "baidu.com"
  - 协议栈关系：Server Name Indication扩展，用于服务端选择正确的证书

### `default_config` : SSL上下文详细配置
引用于 `ctx` 配置项的元素，对该`ctx`进行详细配置，这是协议栈的核心配置。

#### 协议版本配置
- `version`: 配置`ctx`的版本，可参考`test_cfg_parser.cpp:g_convertMap<TlsVersion>`
  - 协议栈关系：指定TLS协议版本（tls1_0、tls1_1、tls1_2、tls1_3、tlcp、dtls1_2等）
- `VersionForbid`: 禁用`ctx`的版本，例如："VersionForbid":"tls1.3"
  - 协议栈关系：禁用特定的TLS协议版本，用于安全加固

#### 证书配置
- `certs`: 证书配置数组，可配置多组证书引用自顶层`cert`配置中的元素
  - 协议栈关系：配置本端可使用的证书链，支持多证书配置（如RSA、ECDSA等）

#### 密码学配置
- `cipher_suite`: 算法套配置，可参考`test_cfg_parser.cpp:g_convertMap<CipherSuite>`
  - 协议栈关系：指定支持的加密算法套件，影响握手协商和后续数据加密
- `group`: 群组配置，可参考`test_cfg_parser.cpp:g_convertMap<SupportedGroups>`
  - 协议栈关系：指定支持的椭圆曲线群组，用于(E)CDHE密钥交换
- `sign_algo`: 签名算法配置，可参考`test_cfg_parser.cpp:g_convertMap<SignAlgo>`
  - 协议栈关系：指定支持的数字签名算法，用于证书验证和签名

#### 证书验证配置
证书认证模式，`true` or `false` **字符串格式**，对应协议栈的证书验证模块。

- `verify_peer`: 是否认证对端证书，如果认证失败会断链
  - 协议栈关系：控制是否验证对端证书的有效性，影响安全性
- `verify_once`: 是否认证一次客户端证书
  - 协议栈关系：控制是否在重协商时跳过客户端证书验证
- `verify_pha`: 是否开启pha（Post-Handshake Authentication）
  - 协议栈关系：TLS 1.3握手后认证功能，允许在握手后请求客户端证书
- `verfiy_fail_if_no_cert`: 拒绝客户端空证书
  - 协议栈关系：当客户端不发送证书时是否拒绝连接
- `verify_keyUsage`: 设置是否进行keyusage检查；例："verify_keyUsage" : "true"
  - 协议栈关系：检查证书的KeyUsage扩展，确保证书用途正确

#### PSK配置
外部定义psk配置，对应协议栈的PSK握手模式。

- `psk_identity`: 配置的psk identity **字符串格式**
  - 协议栈关系：PSK的标识符，用于在PSK握手时标识密钥
- `psk_secret`: 配置的psk密钥 **字符串格式**
  - 协议栈关系：预共享密钥，用于PSK握手模式
- `psk_hint`: 配置的psk hint **字符串格式**
  - 协议栈关系：服务端给客户端的PSK提示，帮助客户端选择正确的PSK

#### TLS 1.3会话配置
- `tls13_session`: 配置引用的是哪个`session`
  - 协议栈关系：使用预定义的会话参数进行TLS 1.3会话恢复

#### PSK模式配置
- `allow_psk_only`: 配置是否支持psk only模式，"true" or "false" **字符串格式**
  - 协议栈关系：是否允许仅使用PSK进行握手，不进行证书验证

#### 重协商配置
- `allow_renegotiation`: 配置是否支持重协商，默认不支持，"true" or "false" **字符串格式**
  - 协议栈关系：控制是否允许在连接建立后进行重协商，影响安全性

#### DTLS Cookie配置
- `allow_cookieExchange`: 配置是否需要cookie exchange，默认支持，"true" or "false" **字符串格式**
  - 协议栈关系：DTLS协议的Cookie交换机制，用于防止DoS攻击

#### 安全配置
- `security_level`: 配置安全等级，默认为 1，数字类型
  - 协议栈关系：控制协议栈的安全策略，影响算法选择和密钥长度
- `session_timeout`: 配置产生的session超时时间，数字类型
  - 协议栈关系：会话缓存的有效期，影响会话恢复的成功率

#### SNI配置
- `sni`: 配置服务端的sni回调，传参用于设置服务端匹配客户端sni时的字符串，字符串类型；例："sni" : "baidu.com"
  - 协议栈关系：服务端SNI处理，根据客户端发送的SNI选择对应的证书

#### 扩展功能配置
- `allow_ResumptionOnRenego`: 设置是否支持重协商时进行会话恢复，bool类型；例："allow_ResumptionOnRenego" : "true"
  - 协议栈关系：重协商时是否允许使用会话恢复
- `recordsizelimit`: 设置record size limit大小，int类型；例："recordsizelimit" : 100
  - 协议栈关系：TLS记录层的大小限制，影响分片策略
- `allow_enc_then_mac`: 设置是否开启EncThenMac，bool类型；例："allow_enc_then_mac" : "true"
  - 协议栈关系：TLS 1.2及以下版本的加密-then-MAC扩展
- `allow_LegacyRenegotiate`: 设置是否开启客户端强校验服务端安全重协商，bool类型；例："allow_LegacyRenegotiate" : "true"
  - 协议栈关系：控制是否允许不安全的传统重协商
- `allow_ExtenedMasterSecret`: 设置是否开启拓展主密钥，bool类型；例："allow_ExtenedMasterSecret" : "true"
  - 协议栈关系：扩展主密钥（EMS）扩展，增强会话密钥的安全性
- `allow_ClientRenegotiate`: 设置是否允许客户端发起重协商，bool类型；例："allow_ClientRenegotiate" : "true"
  - 协议栈关系：控制是否允许客户端主动发起重协商
- `allow_DhAuto`: 设置是否开启dhauto，当使用dhe算法套的时候必须开启，bool类型；例："allow_DhAuto" : "true"
  - 协议栈关系：自动生成DH参数，用于DHE密钥交换
- `quiet_shutdown`: 设置是否开启安静断链，当使用安静断链时开启，bool类型；例："quiet_shutdown" : "true"
  - 协议栈关系：控制是否发送close_notify alert后再关闭连接
- `allow_NewSessionTicket`: 设置是否支持NewSessionTicket扩展，bool类型；例："allow_NewSessionTicket" : "true"
  - 协议栈关系：TLS 1.3的会话票据机制，用于会话恢复
- `alpnlist`: 设置alpn，例："alpnlist" :"http/1.1"
  - 协议栈关系：应用层协议协商（ALPN）扩展，用于协商应用层协议
- `allow_SendFallBackScsv`: 设置是否发送TLS_FALLBACK_SCSV，只对客户端生效
  - 协议栈关系：降级保护信号，防止协议降级攻击
- `allowMiddleBoxCompat`: 设置是否开启中间盒模式，只在tls1.3模式生效，默认开启。bool类型；例："allowMiddleBoxCompat" : "true"
  - 协议栈关系：TLS 1.3的中间件兼容模式，影响ChangeCipherSpec的处理

### `action` : 执行的命令配置
执行的命令，数组类型，元素为json对象，默认会循环执行，对应协议栈的连接生命周期管理。

#### 通用配置
- `ignore_ret`: 只能配字符串的"true"，忽略返回值，继续执行下一条action。例："ignore_ret" : "true"
  - 协议栈关系：控制是否忽略操作失败，继续执行后续步骤

#### 命令类型配置
- `cmd`: 必选字段，标记执行的命令类型，可参考`test_cfg_parser.cpp:g_convertMap<ActionCmd>`

##### `create_ssl`: 创建ssl链路
- `obj`: 目标`ssl`名称
  - 协议栈关系：创建SSL连接对象，初始化连接状态机

##### `accept`: TLS accept（服务端）
- `obj`: 目标`ssl`名称
- `loop`: 是否循环调用，可填`true` or `false` 字符串格式
- `time_out`: 超时时间，单位秒，与loop配合使用
  - 协议栈关系：服务端接受客户端连接，执行TLS握手

##### `connect`: TLS connect（客户端）
- `obj`: 目标`ssl`名称
- `loop`: 是否循环调用，可填`true` or `false` 字符串格式
- `time_out`: 超时时间，单位秒，与loop配合使用
  - 协议栈关系：客户端主动发起TLS连接，执行TLS握手

##### `read`: 读取一条tls消息
- `obj`: 目标`ssl`名称
- `loop`: 是否循环调用，可填`true` or `false` 字符串格式
- `time_out`: 超时时间，单位秒，与loop配合使用
- `echo`: 读取成功后，会自动将读到的内容写回。可配置`true` or `false` 字符串格式，非必选配置项
  - 协议栈关系：从TLS连接读取应用层数据，解密后返回

##### `write`: 写出一条tls消息
- `obj`: 目标`ssl`名称
- `loop`: 是否循环调用，可填`true` or `false` 字符串格式
- `time_out`: 超时时间，单位秒，与loop配合使用
- `from`: 可配置`stdin`，可从标准输入读取信息，然后写出
  - 协议栈关系：向TLS连接写入应用层数据，加密后发送

##### `close`: 关闭链接
- `obj`: 目标`ssl`名称
- `loop`: 是否循环调用，可填`true` or `false` 字符串格式
- `time_out`: 超时时间，单位秒，与loop配合使用
  - 协议栈关系：关闭TLS连接，释放资源，发送close_notify alert

##### `save_session`: 握手成功后保存session
- `obj`: 目标`ssl`名称
- `target_session`: 保存的session名称
  - 协议栈关系：保存当前会话的状态和参数，用于后续会话恢复。注意client应在握手后读取到new session ticket之后再保存

##### `set_session`: 配置会话恢复使用的session
- `obj`: 目标`ssl`名称
- `target_session`: 使用的session名称
  - 协议栈关系：设置会话恢复时使用的预共享密钥或会话票据

##### `key_update`: TLS 1.3密钥更新
- `obj`: 目标`ssl`名称
- `need_requested`: 是否需要对端响应(双向key update)
  - 协议栈关系：TLS 1.3的密钥更新机制，定期更新应用层密钥

##### `verify_client`: TLS 1.3握手后认证
- 协议栈关系：Post-Handshake Authentication，在握手后请求客户端证书

##### `renegotiate`: 发起重协商
- 协议栈关系：在已建立的连接上发起重协商，更新连接参数

##### `end_loop`: 停止循环
- 协议栈关系：停止action循环，结束测试

---

## 配置项与协议栈模块的对应关系总结

| 配置类别 | 协议栈模块 | 说明 |
|---------|------------|------|
| `socket` | 传输层 | 配置TCP/UDP传输参数 |
| `sslCtx` | 上下文管理 | 全局配置对象，包含协议版本、密码套件等 |
| `ssl` | 连接管理 | 具体连接对象，维护连接状态 |
| `cert` | 证书管理 | 证书链、私钥、CRL等配置 |
| `session` | 会话管理 | 会话恢复、PSK配置 |
| `action` | 连接生命周期 | 握手、数据传输、关闭等操作 |

---

## 协议栈适配要点

对于Rust TLS协议栈的适配，需要确保JSON配置文件中的所有配置项都能正确映射到协议栈的对应功能：

1. **传输层适配**：正确解析`socket`配置，建立TCP/UDP连接
2. **上下文配置适配**：将`default_config`中的配置项映射到协议栈的上下文API
3. **证书管理适配**：支持多证书配置，正确加载证书链和私钥
4. **密码学配置适配**：支持协议版本、密码套件、群组、签名算法的配置
5. **会话管理适配**：支持会话恢复、PSK、NewSessionTicket等功能
6. **连接生命周期适配**：正确实现create_ssl、connect/accept、read/write、close等操作
7. **扩展功能适配**：支持SNI、ALPN、KeyUpdate、Renegotiation等扩展功能

通过正确实现上述配置项的解析和映射，Rust TLS协议栈可以无缝集成到测试框架中，实现与其他TLS协议实现一致的测试能力。