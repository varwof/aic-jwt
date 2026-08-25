# AIC-JWT

AIC-JWT（`draft-wei-aic-jwt-00`）的参考实现与验证程序：把草案的规范要求翻译成
可执行的测试，并用真实 OAuth 场景（RFC 9068 / 7523 / 8693 / 9449、OBO、
Token Status List）验证端到端行为。

- Go 参考实现：`github.com/varwof/aic-jwt`（本仓库），核心逻辑在
  `github.com/varwof/types/aicjwt`（单一实现源）。
- TypeScript/WebCrypto 实现：`ts/`（纯 WebCrypto，浏览器可运行，Node 可直接测试）。

## 草案

- `draft-wei-aic-jwt-00.md`（本仓库内副本）

## 运行

```bash
go test ./... -v      # Go 全部测试（含 OAuth 场景）
go test -cover ./...  # 覆盖率
node --test ts/aicjwt.test.ts   # TS/WebCrypto 15 用例（Node 22+）
```

## 目录结构

| 文件 | 作用 |
|------|------|
| `reexport.go` | 包装层：re-export `types/aicjwt` 的 claims/JWS/匹配/约束/密钥绑定/11 步验证 API |
| `oauth.go` | OAuth 协议层：AS（assertion/code/token-exchange）、RS、DPoP、状态列表 |
| `oauth_scenarios_test.go` | 9 个 OAuth 实战场景 |
| `helpers_test.go` | 场景测试辅助（签发/构造令牌） |
| `ts/` | 浏览器 WebCrypto 参考实现（独立于 Go 侧） |
| `draft-wei-aic-jwt-00.md` | 草案副本 |

## 架构

核心逻辑（claims 模型、JWS、能力匹配、约束求值、密钥绑定、11 步验证管线）
统一位于 **`github.com/varwof/types/aicjwt`**；本仓库保留 OAuth 协议层模拟、
场景测试与 TS 浏览器实现。未来功能将逐步并入 varwof 主仓库。

## License

Apache-2.0
