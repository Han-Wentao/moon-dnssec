# MoonDNSSEC

面向调用方提供的、未压缩 **IN 类资源记录集合（RRset）** 的有界 **DNSSEC 离线认证库**。

- 模块：**`Han-Wentao/moon-dnssec@0.1.1`**
- 许可证：**Apache-2.0**
- `0.1.1` 为中文文档补丁版本，验证引擎与公共 API 相对 `0.1.0` 不变。

本项目是验证库，**不是**递归解析器、DNS 报文解析器、区域文件解析器或 DNSSEC 部署规划器。解析出 DNSKEY 或找到 DS 记录并不意味着建立了信任。本项目未经独立安全审计，也不宣称已经达到生产安全应用标准。

## 安装

在使用方 MoonBit 模块中执行：

```sh
moon add Han-Wentao/moon-dnssec@0.1.1
```

在使用方包的 `moon.pkg` 中加入：

```moonbit
import {
  "Han-Wentao/moon-dnssec" @dns,
}
```

模块依赖 MoonCrypt `0.3.1` 和 MoonZoneGuard `0.3.0`。请使用兼容的 MoonBit 工具链；本地实测版本与 CI 平台差异见 [验证说明](docs/ci.md)。

## 运行三个使用流程

在本仓库根目录执行：

```sh
moon test --target js --deny-warn
moon run --target js examples/offline
```

预期输出如下；保留英文输出，便于与可执行示例逐行核对：

```text
resolver: signed child answer; cache TTL=40
authoritative: canonical signing bytes=66
audit: NSEC NXDOMAIN=Secure
audit: NSEC3 NXDOMAIN=Secure
```

示例使用通过 Node.js OpenSSL 独立签名的公开合成快照，**不包含私有签名材料**。测试时间明确设为 `150/160`；如果改用当前真实时间，已经过期的 RRSIG 必须被拒绝，不能将该示例当成实时 DNS 回答。

1. **解析器集成**：输入可信锚、完整 DNSKEY 集合、已签名的父区 DS 与子区 DNSKEY 集合，认证回答并取得剩余缓存 TTL。库不会主动获取记录，也不会将“网络上存在某记录”当成可信依据。
2. **权威 DNS 工具**：输入签名结果，重建规范化签名输入，检查签名、密钥标识、名称标签重建和时间窗口。返回字节可与独立生成的签名数据比对。
3. **离线安全审计**：重放已签名的 NSEC/NSEC3 证明快照与查询，取得受限的 NODATA、NXDOMAIN、委派分类或明确失败结果。仅解析出的 NSEC 结构不能冒充已经认证的证据。

## API 调用流程

相关操作通过 `Result` 显式返回错误。处理不可信输入时应使用模式匹配，而不是直接 `unwrap`；示例中的 `unwrap` 只针对固定且预期成功的测试数据。

- `Name::parse` 接受绝对 ASCII 文本域名；`Name::from_wire` 接受不使用压缩、可以规范化的二进制标签。根域名编码为单个零字节。
- `Record::new(owner, type, ttl, rdata)` 检查线格式字段边界；记录类别固定为 IN。
- `Dnskey::parse`、`Ds::parse`、`Rrsig::parse` 解析受大小约束的记录数据。
- `anchor_keys` 使用带外可信密钥认证**完整的 DNSKEY RRset**。
- `delegate_keys` 验证已签名的父区 DS、关联子区密钥、认证完整的子区 DNSKEY 集合，并限制链深度和继承的有效期。
- `authenticate_rrset` 接收 `TrustedKeys`；较底层的 `authenticate_with_key` 要求调用方明确承担该密钥可信的前提。两者都不能单独证明完整 DNS 响应安全。
- `signing_input` 对规范化 RDATA 排序、去重，使用原始 TTL，并根据 RRSIG 标签数重建通配符所有者名称。
- `nsec_nodata` / `nsec3_nodata` 要求精确名称匹配、已经认证的证明。
- `nsec_nxdomain` / `nsec3_nxdomain` 要求最近包围者（closest encloser）、更近一级名称（next closer）和通配符不存在的完整证明。缺少闭环时返回 `Indeterminate`，不会凭空报告成功。
- `AuthenticatedSet::cache_records` 返回复制后的记录数组，TTL 限制为剩余有效期。

公共接口记录在 [`pkg.generated.mbti`](pkg.generated.mbti)。完整可执行用法见 [`examples/offline/main.mbt`](examples/offline/main.mbt)；[`integration/proof_test.mbt`](integration/proof_test.mbt) 仅通过公共 API 验证真实签名的 NSEC/NSEC3 证明闭环。

## 支持范围与明确限制

| 领域 | 已支持 | 不支持或受限 |
| --- | --- | --- |
| 签名 | RSA/SHA256（8）、RSA/SHA512（10）、P256/SHA256（13）、P384/SHA384（14）、Ed25519（15） | RSA/SHA1、Ed448、算法协商与网络策略 |
| RSA 参数 | 1024–4096 位完整长度的奇数模数、有界指数、PKCS1 v1.5 | 更大 RSA 密钥、PSS DNSSEC 变体 |
| DS 关联 | 摘要类型 2（SHA256），直接复用 MoonZoneGuard | SHA1/SHA384 DS 接受、非 ASCII 的 DS 所有者名称 |
| 含名称的 RDATA | NS、CNAME、PTR、DNAME、MX、SRV、SOA、NSEC | 对已知但尚未实现的含名称类型按安全失败处理 |
| 其他 RDATA | A/AAAA 长度检查、TXT 字符串检查、不透明 RFC3597 数据 | 全部 IANA RR 类型的完整语义解析 |
| 不存在证明 | 精确名称 NODATA、显式最近包围者 NXDOMAIN、精确不安全委派证明 | 通配符 NODATA、推断 NSEC 空非终结点、opt-out 委派发现 |
| NSEC3 | SHA1、盐与迭代次数限制、base32hex、单一参数集合 | opt-out 一般 NXDOMAIN 返回 `Indeterminate` |
| 信任 | 显式可信锚、调用方提供的已签名委派 | RFC5011 密钥轮换、根锚自动获取、在线发现信任链 |

虽然名称解析器可以处理二进制标签，但复用的 DS / key-tag 关联 API 只接受 ASCII 主机标签。这是实际限制，**不代表完整支持国际化域名（IDN）**。

**对由通配符展开的正向 RRset，仅完成签名认证。** 解析器应检查 `is_wildcard_expansion`，并补齐响应级通配符与名称存在性证明。本版本没有实现这一完整正向响应策略。

不存在证明的寿命只表示证明与信任的剩余有效期，不能代替 RFC2308 中基于 SOA MINIMUM 的负缓存处理。报文组装、区域权限边界（bailiwick）、查询匹配、传输、时钟选择、可信锚真实性和负缓存策略均由调用方负责。

## 资源预算与有效期策略

默认上限：256 条记录、1 MiB 签名输入、32 个签名/密钥候选、64 个不存在证明、16 层委派/祖先深度、100 次 NSEC3 迭代。`validate` 会执行硬性上限检查。

签名有效期使用 RFC1982 序列算术；跨越序列空间一半的时间区间、超过一小时的时钟偏差均被拒绝。TTL 不会延长签名或上级信任的寿命；过期与时钟倒退按安全失败处理。

携带信任状态的类型使用私有字段，使用方不能自行构造。导出的数组均为副本；外部编译拒绝测试验证了构造与字段修改攻击会失败。库不使用进程级可变全局信任存储。

## 测试、查重与生态边界

36 项命名测试覆盖核心策略、规范化数据、五组独立 OpenSSL 密码向量、DNSKEY 可信锚、签名委派、已签名 NSEC/NSEC3 公共 API 集成、截断输入、别名/委派边界及缓存；另有 4 项编译拒绝探针验证封装。

CI 对 JS、wasm-gc、wasm、native 执行严格检查与构建，并在 JS、wasm-gc、Linux native 运行测试和示例。普通 wasm 仅验证编译，不宣称执行过运行时测试，也不宣称 Windows 本地 native 验证。命令与工具链说明见 [验证说明](docs/ci.md)。

- [安全策略](SECURITY.md)：威胁模型与问题报告。
- [架构说明](docs/architecture.md)：核心不变量与设计边界。
- [语义查重记录](docs/competition/duplicate-check.md)：有界公开检索、源码比对与相邻项目说明；不是绝对唯一性证明。
- [工程审计](docs/competition/engineering-audit.md)：实现规模与实质提交的保守审计。

MoonZoneGuard 已提供 DS 关联和部署诊断；本库**直接复用**其关联能力，再提供离线密码认证和证明闭环，而不是重复实现并宣称原创。MoonCrypt 提供密码原语；本项目不实现新的密码运算算法。

## 许可、参考与 AI 辅助说明

项目采用 Apache-2.0，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。原创 DNSSEC 验证组合逻辑、数据模型、测试和文档的实现使用了 AI 辅助；参赛者仍对正确性、来源与后续维护负责。

参考规范包括 RFC4034、RFC4035、RFC5155、RFC1982、RFC2181 与 RFC3597；未复制规范正文或上游实现。依赖及许可证边界见 [来源与归属说明](docs/provenance.md)。
