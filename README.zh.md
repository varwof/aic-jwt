# AIC-JWT

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--wei--aic--jwt-blue)](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)

> ⚠️ **预览版** — 不可用于生产环境。API 和功能可能在正式发布前发生变更。
> AIC 草案为 Experimental 状态。欢迎提交 PR 参与贡献（见
> [CONTRIBUTING](https://github.com/varwof/.github)）。

AIC-JWT（`draft-wei-aic-jwt-01`）的参考实现与验证程序：把草案的规范要求翻译成
可执行的测试，并用真实 OAuth 场景（RFC 9068 / 7523 / 8693 / 9449、OBO、
Token Status List）验证端到端行为。

- Go 参考实现：`github.com/varwof/aic-jwt`（本仓库），核心逻辑在
  `github.com/varwof/types/aicjwt`（单一实现源）。
- TypeScript/WebCrypto 实现：`ts/`（纯 WebCrypto，浏览器可运行，Node 可直接测试）。
- X.509 ↔ JWT 桥（草案 §5.4 / Mode B）：`x509_bridge.go`（Go）与
  `ts/x509_bridge.ts` 把 X.509 AIC 扩展映射为 AIC-JWT claims。
- JWT-carrier 路径：`jwt_carrier_test.go` 与 `IssueFromDAShort` 验证
  JWT 载体上的短生命周期、无刷新签发。
- 无服务器浏览器演示：[`demo/`](demo/README.md)——人类 JWT 证书 → 代理证书 → 验证，
  全部在一个自包含 HTML 页面内完成（无需后端）。

**同一套授权语义、两种载体：TLS 层用 X.509，HTTP 层用 JWT。**

## 快速开始

```bash
go test -race ./...          # Go 测试（含 OAuth 场景）
npm run typecheck            # tsc --noEmit
npm run typecheck:tests      # 测试文件的 tsc
node --disable-warning=ExperimentalWarning --experimental-strip-types --test \
  ts/aicjwt.test.ts ts/x509_bridge.test.ts   # TS 单元
npm test                     # demo 库测试
cd verify && npm install && npm run gen \
  && npm run verify:jose && npm run verify:jwt   # 第三方 JWT 验证
npm run build && open demo/dist/index.html      # 浏览器演示
```

## 草案

- AIC-JWT（已备好待发布修订）：[draft-wei-aic-jwt-01.md](docs/draft-wei-aic-jwt-01.md)
  ——RFC 7523 DA claim（DA ver=2）、按模式角色、token exchange 映射（§10.4）。
  datatracker 上当前仍为 -00，待 -01 提交。
- AIC-JWT：[draft-wei-aic-jwt-00.md](docs/draft-wei-aic-jwt-00.md)（另有 `.xml` / `.txt` / `.html`）——在线阅读：[Datatracker](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)
- AIC X.509 配套：[draft-wei-aic-identity-cert-01.md](docs/draft-wei-aic-identity-cert-01.md)（另有 `.xml` / `.txt` / `.html`）——在线阅读：[Datatracker](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/)

仓库内的草案副本为快照（对应 types v0.5.2）；权威文本以 datatracker
发布版本为准。

## 工作原理

AIC-JWT 是 X.509 AIC 同一授权数据模型的 JWT 载体：

- **双层签名**：principal 签署 DA JWT（ver=2）限定代理能力；签发方（CA 或 AS）
  验证 DA 后签署外层 AIC-JWT。
- **按模式角色**：authorized 下 agent 为 `sub`（RFC 7523 §3 item 2A）；
  representative 下资源所有者/principal 为 `sub`、agent 为 `act`；
  担责运营方若不同于资源所有者需独立绑定（future work）。
- **验证**：11 步管线校验 JWS、时间、RFC 7523 DA claim、内外一致性、
  PA（representative）、约束、深度、能力、状态、issuer/audience 与出示者绑定；
  `Decision` 同时给出 actor 与 executor 供审计。
- **接缝**：OAuth RFC 7523/8693 签发与交换已实现；SPIFFE JWT-SVID 投影仅限
  authorized；AIC 语义由本项目验证器校验，标准 JWT 层可由通用 JWT 库消费。

## 运行

```bash
go test -race ./...             # Go 全部测试（含 race、OAuth 场景）
go vet ./...                    # vet
npm run typecheck               # tsc --noEmit
node --test ts/aicjwt.test.ts ts/x509_bridge.test.ts   # TS/WebCrypto 单元 24 用例（Node 22+）
npm test                        # demo 库测试（Node 22+）
cd verify && npm install        # 第三方 JWT 验证依赖
cd verify && npm run gen && npm run verify:jose && npm run verify:jwt
npm run build                   # 构建自包含 demo/dist/index.html
open demo/dist/index.html       # 无服务器浏览器演示，默认英文（中文版 index.zh.html）
```

## 目录结构

| 文件 | 作用 |
|------|------|
| `reexport.go` | 包装层：re-export `types/aicjwt` 的 claims/JWS/匹配/约束/密钥绑定/11 步验证 API |
| `oauth.go` | OAuth 协议层：AS（assertion/code/token-exchange）、RS、DPoP、状态列表 |
| `x509_bridge.go` | X.509 AIC 扩展 → AIC-JWT claims（MapX509ToClaims，§5.4 Mode B） |
| `jwt_carrier_test.go` | JWT-carrier 集成测试（短生命周期签发、跨载体单密钥、JOSE 完整性） |
| `oauth_scenarios_test.go` | 9 个 OAuth 实战场景 |
| `helpers_test.go` | 场景测试辅助（签发/构造令牌） |
| `ts/` | 浏览器 WebCrypto 参考实现（独立于 Go 侧） |
| `ts/asn1.ts`、`ts/x509_bridge.ts` | TS ASN.1 解析 + X.509→JWT 桥 |
| `demo/` | 无服务器浏览器演示（TS 库 + UI，构建为自包含 HTML） |
| `verify/` | 第三方 JWT 验证（jose、jsonwebtoken）针对生成 fixture |
| `docs/draft-wei-aic-jwt-01.md` | 已备好的 -01 修订副本 |

## 变更与验证（2026-09-06）

近期变更对应 OAuth WG 评审（Lombardo/Schrock，2026-09-04）：

- **RFC 7523 断言**：DA JWT 现携带 `iss`/`sub`/`aud`/`exp`/`iat`/`jti`
  （jti=nonce；exp=ts+requested_lifetime），DA `ver` 为 2——-00 形状的 DA
  被显式拒绝，而非静默降级。
- **按模式角色**：representative 下资源所有者在 `sub`、代理在 `act`；
  authorized 下代理在 `sub`（RFC 7523 §3 item 2A）。一致性检查与验证决策
  （`Executor` 与 `Actor` 并列）已同步。
- **Token exchange**：映射在 -01 §10.4 声明；representative token 不能当
  actor 凭据。
- **依赖**：`github.com/varwof/types` v0.5.2。
- **第三方验证**：`verify/` 用 `jose` 与 `jsonwebtoken` 验证 AIC-JWT 是
  可被通用 JWT 库消费的标准 JWT（签名/iss/aud/exp）；AIC 特有语义仍由
  AIC-JWT 参考实现验证。

## 证据与边界

- Go 套件在 `go test -race`/`go vet` 下通过；TS 源码与测试均过 `tsc`。
  覆盖率：types pki 92%、types/aicjwt 88%、types/cmd 88%、aic-jwt 90%。
- 第三方 JWT 验证（jose / jsonwebtoken）通过——见
  [verify/RESULTS.md](verify/RESULTS.md)。
- 浏览器 demo 覆盖正常路径及越权/过期/篡改/身份伪造/约束违规场景。
- 与 EMILIA 的独立联合验证见
  [emiliaprotocol/emilia-protocol#730](https://github.com/emiliaprotocol/emilia-protocol/pull/730)。

边界：本项目实现 AIC-JWT 语义及其声明的 OAuth 7523/8693 接缝，不是完整的
OAuth 授权服务器实现；通用 JWT 库只校验标准 JWT 层；草案为 Experimental，
datatracker 当前为 -00，待 -01 发布。

## 演示

[`demo/`](demo/README.md) 页面用 WebCrypto 在浏览器内完整演示 AIC-JWT 生命周期：

1. 人类生成密钥对，自签「主体授权证书」（PA JWT）——人类 JWT 证书，含身份绑定与 P_grants。
2. 代理构建委托请求（含 32 字节 nonce），人类审阅并签署 DA JWT。
3. 演示 CA 校验 DA 并签发外层 AIC-JWT（代理证书），通过 `cnf.jkt` 绑定代理公钥。
4. 网关执行 11 步验证管线（外加身份绑定检查），逐项输出审计报告；
   内置越权、过期、篡改、身份伪造、约束违规等拒绝场景。

直接用 Chrome 打开 `demo/dist/index.html`，或加 `?auto` 参数自动跑完整流程。

## 架构

核心逻辑（claims 模型、JWS、能力匹配、约束求值、密钥绑定、11 步验证管线）
统一位于 **`github.com/varwof/types/aicjwt`**；本仓库保留 OAuth 协议层模拟、
场景测试与 TS 浏览器实现。未来功能将逐步并入 varwof 主仓库。

## License

Apache-2.0
