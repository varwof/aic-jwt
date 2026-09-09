# ts/ —— TypeScript harness（AIC → WIT/WPT）

> ⚠️ **EXPERIMENTAL (2026-09)**: exploratory WIT/WPT interop study artifact; 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

仅用 Node 内置模块（`node:crypto`、`node:assert`、`node:test`），**零 npm 依赖**，
运行在 Node 22 的 `--experimental-strip-types` 直跑 `.ts`。与 `wit-wpt-interop/go/`
是同一套语义的镜像：字段名、场景编号 S1..S11、期望全部一致。

## 文件

| 文件 | 职责 |
|------|------|
| `src/jose.ts` | base64url、compact JWS、ES256 签名/验签（`dsaEncoding: 'ieee-p1363'`） |
| `src/jwk.ts` | JWK <-> `KeyObject`（`createPublicKey({format:'jwk'})`）、RFC 7638 jkt、`key_hash`、本地生成 |
| `src/types.ts` | 与 Go 同名字段/结构 |
| `src/subset.ts` | C_agent ⊆ P_grants 判定 + 约束 fail-closed（与 Go 同规则） |
| `src/issuer.ts` | AIC-aware 发放服务（`Issuer.issue(da, paOpt, agentId, now)`） |
| `src/verifier.ts` | 验证管线 + `mintWPT` + 防重放 | 
| `src/scenarios.test.ts` | S1..S11 场景矩阵（node:test） |

## 运行

```sh
# 仓库根目录
node --disable-warning=ExperimentalWarning --experimental-strip-types --test wit-wpt-interop/ts/src/scenarios.test.ts
```

## 语义边界与对应（与 go/README.md 相同）

- **issuance-control / 发放策略侧**对接：AIC DA/PA 校验发生在 WIT-SVID 签发前，
  不塞进 FetchWITSVID RPC（请求侧无携带证书/令牌的字段）。
- WIT-SVID = **身份 + PoP（cnf）凭证**，不携带 AIC capabilities/constraints；
  entitlement 落在签发记录 `WITGrant.entitlement`，由资源服务器部署策略使用。
- cnf 私钥（`wit_svid_key`）由发放服务生成随响应下发，与 AIC DA 绑定的 agent
  密钥是 issuance-time 映射。
- WIT MUST NOT 作为 bearer，必须配 WPT（无 WPT → DENY）。

| 草案 | 落点 |
|------|------|
| draft-wei-aic-jwt-01 §5/§8 | DA/PA 形状、delegation_mode、unknown constraint fail-closed、key_hash |
| draft-ietf-wimse-workload-creds | `typ=wit+jwt`、`cnf.jwk(+alg)`、非对称非 none、WIT 不做 bearer |
| SPIFFE WIT-SVID profile | `kid` REQUIRED、`sub=spiffe://`、`aud` MUST NOT、下发 `wit_svid_key` |
| draft-ietf-wimse-wpt-02 | `typ=wpt+jwt`、aud=target URI、短 exp、128-bit jti、`wth`、`Authorization: WPT` |