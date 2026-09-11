# wit-wpt-interop —— AIC → WIT/WPT 互操作 harness

> ⚠️ **EXPERIMENTAL (2026-09)**: exploratory WIT/WPT interop study artifact; 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

> **params 语义规范出处**：本 harness 的 params subset 语义来自 **CLC-v1 §6.2**
> （https://github.com/varwof/capability/blob/clc-v1.1/docs/capability-language-core-v1.md ，v1.1 数组 enum 语义）。
> 此处是实现其在 AIC-JWT / WIT 场景下的用法，C 语言核不另设参数规则。

> **对齐记录（2026-09-11）**：aligned to CLC-v1 §6.2 (v1.1) — **array = allowed-set**；
> scalar number grant keeps **bound** semantics。此前（v1.1 前）本 harness 使用
> array-as-bound 语义（数组内数字按上界递归比较），已在 go/subset.go 与两处
> subset.ts 同步修正（见 `clc-v1-ambiguities.md` 第 4 条）。

本目录是 AIC-JWT 之外的**新增**互操作交付：把“AIC principal 签发的授权（DA/PA）作为
issuance-control 输入”用 Go 与 TypeScript 各实现一遍同一套场景矩阵（S1..S11）。

```
go/   —— 独立 Go module（module witwpt.local/interop，仅标准库，ES256/P-256）
ts/   —— TypeScript harness（Node 22 type stripping，仅 node:crypto，零 npm 依赖）
```

## 语义边界（与任务文档第 0 节一致）

- Pieter 的建议是把 AIC 作为 SPIFFE Workload API / WIT-SVID 供给的**上游授权输入**。
- SPIFFE Workload API 的 FetchWITSVID 等请求侧**没有携带证书/令牌的字段**（规范 §4.1）；
  因此本 harness 演示的是 **issuance-control / 发放策略侧**的对接：一个 AIC-aware 的
  SPIFFE 发放服务在签发 WIT-SVID 前校验 AIC DA/PA。
- WIT-SVID 是**身份 + PoP（cnf）凭证**，不携带 AIC capabilities/constraints；通用 WIT
  接收方只认 SPIFFE 身份并忽略未知 claims。AIC 的授权语义落在**签发时的 entitlement
  决策**（落进 graant 的 `entitlement []Capability`，供资源服务器部署策略使用）。
- 标准 FetchWITSVID 语义下 WIT 的 cnf 私钥由发放服务生成并随响应下发（`wit_svid_key`）。
  本 harness 采用**发放服务生成 WIT 密钥对**；它与 AIC DA 所绑定的 agent 密钥的关系是
  issuance-time 映射，不是同一把密钥。

## 运行命令

```sh
# Go harness
cd wit-wpt-interop/go && go test ./... -v

# TS harness（仓库根目录，Node ESM 沿目录向上解析）
cd .. && node --disable-warning=ExperimentalWarning --experimental-strip-types --test wit-wpt-interop/ts/src/scenarios.test.ts
```

## 与规范草案的对应

| 规范 | 本 harness 的落点 |
|------|-------------------|
| draft-wei-aic-jwt-01 §5/§8 | DA/PA 形状、delegation_mode、unknown constraint fail-closed、key_hash |
| draft-ietf-wimse-workload-creds（WIT） | `typ=wit+jwt`、`cnf.jwk(+alg)`、非对称、非 none |
| SPIFFE WIT-SVID profile（Incubating） | `kid` REQUIRED、`sub=spiffe://`、`aud` MUST NOT、服务端下发 `wit_svid_key` |
| draft-ietf-wimse-wpt-02 | `typ=wpt+jwt`、aud=target URI、短 exp、128-bit jti、`wth=SHA-256(WIT)` |

## subset 语义（scheme-specific 实现点）

C_agent ⊆ P_grants：同 scheme + id 精确或通配匹配（`*`、`**`、`{a,b}`、`[a-z]`，
段内匹配即可）+ params 递归 subset（按 **CLC-v1 §6.2 v1.1**：
number（标量 grant 值）= 上界，agent ≤ grant；**array = 允许值集合（enum）**——
请求标量须为成员、请求数组每个元素须为成员、数组内数字按**精确相等**；
object：递归；其它：精确相等）。需要由 scheme 定义的部分用显式注释留出扩展点，
不声称是 AIC-JWT 的通用算法。
