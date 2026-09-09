// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// 用仓库本地 esbuild 把 src/main.ts 打包为 IIFE 并内联进 template.html，
// 产出单文件自包含页面 dist/index.html（可 file:// 直接打开）。
// 用法：cd REPO && node wit-demo/scripts/build.mjs

import { build } from "esbuild";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const demo = join(root, "wit-demo");

const result = await build({
  entryPoints: [join(demo, "src/main.ts")],
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

const html = template
  .replaceAll(
    "__LANG__",
    "en",
  )
  .replaceAll(
    "__TITLE__",
    "WIT-SVID Issuance-Control Demo · AIC DA/PA gate → WIT-SVID → WPT PoP → Report",
  )
  .replaceAll(
    "__FOOTER__",
    "All keys and signatures are generated locally with WebCrypto; nothing leaves the browser. The trust domain and issuer are simulated locally for protocol illustration.",
  )
  .replace(
    /<script>\s*\/\*__APP_JS__\*\/\s*<\/script>/,
    () => `<script type="module">\n${js}\n</script>`,
  );

await mkdir(join(demo, "dist"), { recursive: true });
await writeFile(join(demo, "dist", "index.html"), html);
console.log(`wrote ${join(demo, "dist", "index.html")} (${html.length} bytes)`);