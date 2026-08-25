# AIC-JWT

AIC-JWT（`draft-wei-aic-jwt-00`）的参考实现与验证程序：把草案的规范要求翻译成
可执行的测试，并用真实 OAuth 场景（RFC 9068 / 7523 / 8693 / 9449、OBO、
Token Status List）验证端到端行为。

- Go 参考实现：`github.com/varwof/aic-jwt`（本仓库），核心逻辑在
  `github.com/varwof/types/aicjwt`（单一实现源）。
- TypeScript/WebCrypto 实现：`ts/`（纯 WebCrypto，浏览器可运行，Node 可直接测试）。
- 无服务器浏览器演示：[`demo/`](demo/README.md)——人类 JWT 证书 → 代理证书 → 验证，
  全部在一个自包含 HTML 页面内完成（无需后端）。

## 草案

- AIC-JWT：[draft-wei-aic-jwt-00.md](docs/draft-wei-aic-jwt-00.md)（另有 `.xml` / `.txt` / `.html`）——在线阅读：[Datatracker](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)
- AIC X.509 配套：[draft-wei-aic-identity-cert-00.md](docs/draft-wei-aic-identity-cert-00.md)（另有 `.xml` / `.txt` / `.html`）——在线阅读：[Datatracker](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/)

## 运行

```bash
go test ./... -v      # Go 全部测试（含 OAuth 场景）
go test -cover ./...  # 覆盖率
node --test ts/aicjwt.test.ts   # TS/WebCrypto 15 用例（Node 22+）
npm test                        # demo 库测试（Node 22+）
npm run build                   # 构建自包含 demo/dist/index.html
open demo/dist/index.html       # 无服务器浏览器演示，默认英文（中文版 index.zh.html）
```

## 目录结构

| 文件 | 作用 |
|------|------|
| `reexport.go` | 包装层：re-export `types/aicjwt` 的 claims/JWS/匹配/约束/密钥绑定/11 步验证 API |
| `oauth.go` | OAuth 协议层：AS（assertion/code/token-exchange）、RS、DPoP、状态列表 |
| `oauth_scenarios_test.go` | 9 个 OAuth 实战场景 |
| `helpers_test.go` | 场景测试辅助（签发/构造令牌） |
| `ts/` | 浏览器 WebCrypto 参考实现（独立于 Go 侧） |
| `demo/` | 无服务器浏览器演示（TS 库 + UI，构建为自包含 HTML） |
| `draft-wei-aic-jwt-00.md` | 草案副本 |

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
