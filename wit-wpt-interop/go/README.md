# go/ —— Go harness（AIC → WIT/WPT）

> ⚠️ **EXPERIMENTAL (2026-09)**: exploratory WIT/WPT interop study artifact; 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

独立 Go module `witwpt.local/interop`，**仅标准库**（`crypto/ecdsa`、`crypto/sha256`、
`crypto/x509`、`encoding/json`、`regexp`），无任何第三方依赖。与 `wit-wpt-interop/ts/`
是同一套语义的镜像：字段名、场景编号 S1..S11、期望全部一致。

## 文件

| 文件 | 职责 |
|------|------|
| `jose.go` | base64url(no padding)、compact JWS 解析/签名/验签（ES256，P-256/SHA-256，签名原始 R‖S 格式） |
| `jwk.go` | P-256 JWK <-> 密钥互转、RFC 7638 jkt、`key_hash = base64url(SHA-256(SPKI))`、本地生成 |
| `types.go` | `Capability/DA/PA/Principal/Constraint/WITGrant/Request/Decision/CheckResult` |
| `subset.go` | C_agent ⊆ P_grants 的 scheme-specific 判定 + 约束 fail-closed |
| `issuer.go` | AIC-aware 发放服务：DA/PA 校验 + WIT-SVID 签发 |
| `verifier.go` | WIMSE 风格验证管线 + `MintWPT` + 防重放存储 |
| `scenarios_test.go` | S1..S11 表驱动测试 |

## 运行

```sh
go test ./... -v
```

## 语义边界

- 本 harness 是 **issuance-control / 发放策略侧**对接：发放服务在签发 WIT-SVID
  前校验 AIC DA/PA；SPIFFE Workload API 的 FetchWITSVID RPC 请求侧**没有**携带
  证书/令牌的字段，因此 AIC 不塞进 RPC。
- WIT-SVID 是**身份 + PoP（cnf）凭证**，不携带 AIC capabilities/constraints；
  通用 WIT 接收方忽略未知 claims（S3 的 `tamper_flag` claim 正是这个语义——除
  MUST NOT 的 aud 外，多余 claims 只影响字节差异，不影响验签）。
- 标准 FetchWITSVID 语义下 WIT 的 cnf 私钥（`wit_svid_key`）由**发放服务生成**
  并随响应下发（`WITGrant.WITPrivateKey`）。它与 AIC DA 绑定的 agent 密钥是
  issuance-time 映射，不是同一把。
- WIT MUST NOT 作为 bearer 使用，必须配 WPT（无 WPT → DENY）。

## 验证管线（对齐 draft-01 §11 与 WIMSE WPT 语义）

1. header（typ/alg/kid，拒绝 none 与对称算法）
2. WIT 验签（kid → 信任 bundle）
3. WIT 时间（exp；可选 iat/nbf）
4. WIT claims：sub 必须 `spiffe://`；**aud 出现即 DENY**；`cnf.jwk`(+`alg`) REQUIRED
5. WPT 验签（公钥取 WIT `cnf.jwk`，算法必须一致）
6. WPT claims：aud == target URI、exp 短寿命(<=300s)、jti=128-bit 唯一、wth == SHA-256(WIT)
7. PoP 呈现：无 WPT 或未以 `Authorization: WPT <token>` 呈现即 DENY
8. 部署策略：requested capability 超出 entitlement → DENY（reason 前缀 `policy:`）

## 与草案的对应

| 草案 | 落点 |
|------|------|
| draft-wei-aic-jwt-01 §5/§8 | DA/PA 形状、delegation_mode（authorized/representative）、unknown constraint fail-closed、principal.key_hash |
| draft-ietf-wimse-workload-creds | `typ=wit+jwt`、`cnf.jwk(+alg)`、非对称非 none、WIT 不做 bearer |
| SPIFFE WIT-SVID profile | `kid` REQUIRED、`sub=spiffe://`、`aud` MUST NOT、服务端下发 `wit_svid_key` |
| draft-ietf-wimse-wpt-02 | `typ=wpt+jwt`、aud=target URI、短 exp、128-bit jti、`wth`、`Authorization: WPT <token>` |