# wit-demo —— 独立浏览器 WIT demo

> ⚠️ **EXPERIMENTAL (2026-09)**: exploratory WIT/WPT interop study artifact; 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

一个**全新独立页面**（与 `REPO/demo/` 平级，不复用/不修改其源码），单文件产物，
可 `file://` 直接打开。页面演示完整闭环：**AIC DA/PA 门控 WIT-SVID 发放 →
WPT PoP 构造 → 资源服务器（WIMSE 风格）逐项验证报告**。所有密钥/签名在浏览器
内用 WebCrypto 现场生成（`crypto.getRandomValues`），不上传任何数据。

## 运行 / 构建 / 测试

```sh
# 构建单文件产物（复用仓库本地 esbuild）
cd REPO && node wit-demo/scripts/build.mjs
# 打开
open wit-demo/dist/index.html

# typecheck（复用仓库本地 typescript）
cd REPO && node node_modules/typescript/bin/tsc -p wit-demo/tsconfig.json --noEmit

# 测试（Node 22 WebCrypto 复用 lib 逻辑跑 S1/S2/S4/S5/S7/S8/S10）
cd REPO && node --disable-warning=ExperimentalWarning --experimental-strip-types --test wit-demo/test/demo.test.ts
```

## 目录

```
wit-demo/
  template.html          # 占位骨架（__LANG__/__TITLE__/__FOOTER__/APP_JS）
  scripts/build.mjs      # esbuild 打包并内联为单文件 HTML
  tsconfig.json          # strict / ES2020 / noEmit（typecheck 用）
  src/main.ts            # UI 胶水 + 场景驱动（场景选择器 + 逐项报告）
  src/lib/{types,jose,jwk,subset,issuer,verifier}.ts   # 浏览器 WebCrypto 实现
  test/demo.test.ts      # Node 下复用 lib 的 S1/S2/S4/S5/S7/S8/S10
  dist/index.html        # 构建产物（可 file:// 打开）
```

## 页面流程（与 harness 场景一一对应）

1. 生成 Principal（人类）身份与密钥，签名 PA（grants）；（可选项）签名 DA。
2. 构造委托请求（agent_id、能力 C_agent、约束、lifetime、nonce）。
3. AIC-aware 发放服务：校验 DA 签名/key_hash、agent_id、subset、constraints，
   然后生成 WIT 密钥对并签发 WIT-SVID。
4. Agent 构造目标请求（method + target URI）并用 cnf 私钥生成 WPT。
5. 资源服务器按验证管线逐项检查并输出 PERMIT/DENY 报告。

场景选择器至少覆盖：happy path、S2 授权不足（发放拒绝）、S4 错误 PoP 密钥、
S5 aud 不匹配、S7 重放、S8 无 WPT（bearer）、S10 策略拒绝；报告逐项列出检查
（header/signature/time/cnf/wth/aud/jti/pop/policy）与失败原因。

## 语义边界（页面“Semantics”区同文）

- WIT 是**身份 + cnf/PoP 凭证**；AIC 的 principal/capability 绑定发生在
  **发放决策**，不进入 WIT claims（WIT 不携带 AIC capabilities/constraints）。
- 标准 FetchWITSVID 由服务端生成 `wit_svid_key` 随响应下发，本 demo 模拟该语义；
  该密钥与 AIC DA 绑定的 agent 密钥是 issuance-time 映射，不是同一把。
- WIT MUST NOT 作为 bearer 使用，必须配 WPT。
- 与 draft-wei-aic-jwt-01 的关系：本 demo 是 AIC-JWT 之外、SPIFFE WIT-SVID
  供给侧的 issuance-control 对接演示。

## 与草案的对应

| 草案 | 本 demo 的落点 |
|------|----------------|
| draft-wei-aic-jwt-01 §5/§8 | principal 签 DA/PA、delegation_mode、unknown constraint fail-closed |
| draft-ietf-wimse-workload-creds | `typ=wit+jwt`、`cnf.jwk(+alg)`、WIT 不做 bearer |
| SPIFFE WIT-SVID profile | `kid` REQUIRED、`sub=spiffe://`、`aud` MUST NOT、下发 `wit_svid_key` |
| draft-ietf-wimse-wpt-02 | `typ=wpt+jwt`、aud=target URI、短 exp、128-bit jti、`wth` |