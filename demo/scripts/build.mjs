// Builds the self-contained demo pages from the TS sources.
// Two static pages are emitted, each with the language baked in:
//   demo/dist/index.html      -> English (default)
//   demo/dist/index.zh.html   -> Chinese
// No server-side dependencies: each file embeds the whole app and can
// be opened directly in a modern Chrome via file:// or any static host.
import { build } from "esbuild";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const demo = join(root, "demo");

const result = await build({
  entryPoints: [join(demo, "src/app/main.ts")],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: ["chrome110"],
  minify: true,
  write: false,
  logLevel: "warning",
});

const js = result.outputFiles[0].text;
const template = await readFile(join(demo, "template.html"), "utf8");

function buildPage(name, lang) {
  const isEn = lang === "en";
  const [htmlLang, title, footer1, footer2] = isEn
    ? [
        "en",
        "AIC-JWT Serverless Demo · Human Certificate → Delegated Certificate → Verification",
        "All keys and signatures are generated locally in your browser with WebCrypto; nothing is uploaded. The demo CA is simulated locally to illustrate the protocol; for production deployments see",
        "and the companion documents.",
      ]
    : [
        "zh-CN",
        "AIC-JWT 无服务器演示 · 人类证书 → 代理证书 → 验证",
        "本页所有密钥与签名均在浏览器内使用 WebCrypto 现场生成，不上传任何数据。演示 CA 为本地模拟，仅供理解协议流程；生产环境请参考",
        "与配套文档。",
      ];
  const html = template
    .replaceAll("__LANG__", htmlLang)
    .replaceAll("__TITLE__", title)
    .replaceAll("__FOOTER_P1__", footer1)
    .replaceAll("__FOOTER_P2__", footer2)
    .replace(
      /<script>\s*\/\*__APP_JS__\*\/\s*<\/script>/,
      () =>
        `<script>window.__AIC_DEMO_LANG__ = "${lang}";</script>\n<script type="module">\n${js}\n</script>`,
    );
  return writeFile(join(demo, "dist", name), html);
}

await mkdir(join(demo, "dist"), { recursive: true });
await buildPage("index.html", "en");
await buildPage("index.zh.html", "zh");

const kb = (js.length / 1024).toFixed(1);
console.log(`built demo/dist/index.html (en) + demo/dist/index.zh.html (zh), ${kb} KiB JS inlined`);
