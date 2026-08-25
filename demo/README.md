# AIC-JWT 无服务器浏览器演示

一个**零后端依赖**的浏览器演示：在单个页面里完成

> 人类 JWT 证书 → 人类审批授权（DA）→ 演示 CA 签发代理证书（AIC-JWT）→ 网关按 11 步管线验证身份与权限

所有密钥生成、签名与验证都使用浏览器内置的 **WebCrypto** 现场完成，不上传任何数据，也不需要 Node/Python/后端服务。构建产物是**自包含的 HTML 文件**，双击即可在 Chrome 中运行。

提供中英两个独立页面（构建期烘焙语言，与浏览器 locale 无关）：

| 页面 | 语言 | 文件 |
|---|---|---|
| 默认页 | English | `demo/dist/index.html` |
| 中文页 | 简体中文 | `demo/dist/index.zh.html` |

页面内的「语言 / Language」按钮可互相跳转。

## 快速开始

直接打开构建产物（默认英文，中文页打开 `index.zh.html`）：

```
demo/dist/index.html
demo/dist/index.zh.html
```

或带上自动演示参数，打开即自动跑完整流程：

```
demo/dist/index.html?auto
demo/dist/index.zh.html?auto
```

也可以指定验证场景（`happy` / `overreach` / `expired` / `tampered` / `spoofed` / `concurrency`）：

```
demo/dist/index.html?auto=spoofed
```

> 说明：`file://` 在 Chrome 中属于安全上下文，WebCrypto 可用；也可以放到任意静态托管上访问。

## Demo 流程与草案的对应

| Demo 步骤 | 产出 | 草案章节 |
|---|---|---|
| ① 人类生成密钥并自签证书 | 主体授权证书（PA JWT）：身份（realm/id）+ 公钥 jkt 指纹 + P_grants + 委托策略 | §5.3、§5.4、§9.4 |
| ② 代理发起委托请求 | 代理密钥对 + 32 字节 nonce + 目标能力 | §10.1 第 1 步 |
| ③ 人类审批并签署 | DA JWT（人类私钥签名，含能力与约束） | §10.1 第 2 步 |
| ④ 演示 CA 签发 | 外层 AIC-JWT（代理证书）：CA 签名、cnf.jkt 绑定代理公钥、内嵌 DA | §10.1 第 3-5 步 |
| ⑤ 网关验证 | 11 步管线逐项审计报告 + 放行/拒绝决策 | §11 |

验证报告展示的 13 个检查项：草案 §11 的 11 步管线，外加两个与「身份」直接相关的检查——**出示者身份绑定（cnf.jkt，防令牌盗用）**与**签发者/受众核对（iss/aud）**。

## 内置验证场景

| 场景 | 结果 | 展示的价值点 |
|---|---|---|
| 合法请求放行 | PERMIT | 正常委托链路全通过 |
| 越权请求拒绝 | DENY（步骤 9） | 能力评估 fail-closed |
| 令牌过期拒绝 | DENY（步骤 3） | 时间窗口校验 |
| 令牌被篡改拒绝 | DENY（步骤 1） | JWS 签名防篡改 |
| 身份伪造拒绝 | DENY（步骤 12） | cnf.jkt 出示者绑定，防令牌盗用 |
| 并发超限拒绝 | DENY（步骤 7） | 约束（max-concurrent）求值 |
| 越权委托被 CA 拒绝 | 签发失败 | least privilege 在签发阶段生效 |

## 界面中的技术说明

页面底部新增「AIC-JWT 技术说明」专区（随演示步骤实时填充真实值），面向想读懂技术细节的人：

| 面板 | 内容 |
|---|---|
| ① 信任模型与签名链 | 谁签谁、谁信谁：人类签 DA、CA 签外层、网关双钥验证；密钥绑定关系（key_hash / cnf.jkt / issuerKeys） |
| ② 嵌套令牌结构 | 外层 AIC-JWT 内嵌 DA JWT 的两层 JWS 结构；typ 三值防嵌套令牌混淆 |
| ③ Claims 速查表 | 外层 / DA / PA 全部分组的 claims 字段含义与要点 |
| ④ 验证管线详解 | 13 个检查项各自在防什么，失败意味着什么 |
| ⑤ 能力匹配与参数交集 | 通配符匹配与参数交集示例表（含拒绝原因） |
| ⑥ 约束求值与安全要点 | max-concurrent 示例、算法白名单、nonce/DPoP 定位、浏览器密钥说明 |

## 目录结构

```
demo/
├── dist/index.html        # 构建产物：自包含、可直接打开
├── template.html          # HTML/CSS 模板（构建时内联 JS）
├── scripts/build.mjs      # esbuild 打包 → 内联进 index.html
├── src/
│   ├── app/main.ts        # 演示 UI
│   └── lib/               # 演示库（签发 + 验证编排）
│       ├── identity.ts    # 人类身份与 PA 证书
│       ├── delegation.ts  # 委托请求与 DA 签署
│       ├── ca.ts          # 演示 CA：校验 DA、签发代理证书
│       ├── verify.ts      # 11 步验证报告包装
│       ├── scenario.ts    # 场景编排（全流程 + 各拒绝场景）
│       └── types.ts       # demo 数据类型
└── test/demo.test.ts      # 库级测试（Node 22+ 原生 TS 运行）
```

核心密码学（claims 模型、JWS、能力匹配、约束求值、验证管线）复用仓库根目录的
[`ts/aicjwt.ts`](../ts/aicjwt.ts) —— 即草案的浏览器 WebCrypto 参考实现，demo 只在其上做签发流程编排与 UI。

## 开发

```bash
npm install        # 安装 esbuild / typescript（仅开发需要）
npm run build      # 构建 demo/dist/index.html（英文）+ index.zh.html（中文）
npm run typecheck  # tsc 严格类型检查
npm test           # 运行 demo 库测试（9 个用例，Node 22+）
```

## 安全说明（重要）

- 这是**协议演示**，不是生产 CA。演示 CA 的私钥在浏览器内现场生成，会话刷新即丢失，仅用于展示协议流程。
- 浏览器无法访问 TPM/HSM/智能卡密钥，硬件级主体签名与 X.509 链验证建议交给服务端辅助（草案 §10.5 Mode B）。
- 演示使用 `hash_alg: "jkt"`（RFC 7638 JWK 指纹）做密钥绑定，是草案 §9.4 推荐的浏览器部署形式。
- 生产部署请以草案原文为准：[draft-wei-aic-jwt-00](../docs/draft-wei-aic-jwt-00.md)；也可通过 Datatracker 阅读：[draft-wei-aic-jwt](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/) 与 [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/)。
