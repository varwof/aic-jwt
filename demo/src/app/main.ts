// AIC-JWT serverless browser demo UI.
// The whole flow (human certificate -> DA -> CA certificate ->
// gateway verification) runs locally with WebCrypto.
// Two static pages are built from this source: index.html (Chinese)
// and index.en.html (English); a language switch jumps between them.
import { parseCompact } from "../../../ts/aicjwt.ts";
import {
  createHumanIdentity,
  verifyHumanCertificate,
} from "../lib/identity.ts";
import {
  approveDelegation,
  buildDelegationRequest,
  capsWithinGrants,
  createAgentIdentity,
} from "../lib/delegation.ts";
import { createDemoCA, issueAgentCertificate } from "../lib/ca.ts";
import {
  buildVerifierBase,
  demonstrateOutOfScopeIssuance,
  runScenario,
  SCENARIO_META,
} from "../lib/scenario.ts";
import type { DemoWorld } from "../lib/scenario.ts";
import type {
  AgentCertificate,
  AgentIdentity,
  Capability,
  DAApproval,
  DelegationRequest,
  DemoCA,
  HumanIdentity,
  ScenarioId,
  VerifyReport,
} from "../lib/types.ts";
import { getLang, t } from "../lib/i18n.ts";
import type { Lang } from "../lib/i18n.ts";
import { buildTechSection } from "./tech.ts";
import type { LiveValues } from "./tech.ts";

const app = document.querySelector("#app") as HTMLElement;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const AGENT_CAPS: Capability[] = [
  { scheme: "database", id: "query:SELECT", params: { max_rows: 100 } },
];
const CONSTRAINTS: Capability[] = [
  { scheme: "varwof/constraint-v1", id: "max-concurrent", params: { max: 5 } },
];

interface UiState {
  human?: HumanIdentity;
  agent?: AgentIdentity;
  request?: DelegationRequest;
  da?: DAApproval;
  ca?: DemoCA;
  certificate?: AgentCertificate;
  now: Date;
}
const ui: UiState = { now: new Date() };
let techSection: HTMLElement;
let lastReport: VerifyReport | undefined;
let lastScenario: ScenarioId | undefined;

// ---- tiny DOM helpers ---------------------------------------------------

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

function btn(
  label: string,
  onClick: () => void,
  opts: { primary?: boolean; danger?: boolean; id?: string } = {},
): HTMLButtonElement {
  const b = el("button");
  if (opts.primary) b.classList.add("primary");
  if (opts.danger) b.classList.add("danger");
  if (opts.id) b.id = opts.id;
  b.textContent = label;
  b.addEventListener("click", onClick);
  return b;
}

function row(...children: HTMLElement[]): HTMLElement {
  const d = el("div", "row");
  for (const c of children) d.append(c);
  return d;
}

function panel(
  title: string,
  no: number | null,
  body: HTMLElement[],
): HTMLElement {
  const s = el("section", "panel");
  const h = el("h2");
  if (no !== null) {
    h.append(el("span", "step-no", String(no)), el("span", undefined, title));
    s.dataset.step = String(no);
  } else {
    h.textContent = title;
  }
  s.append(h);
  for (const node of body) s.append(node);
  return s;
}

function card(children: HTMLElement[], title?: string): HTMLElement {
  const c = el("div", "card");
  if (title) c.append(el("p", "muted", title));
  for (const node of children) c.append(node);
  return c;
}

// ---- log stream ----------------------------------------------------------

const logBox = el("div", "log");
function log(text: string, cls: "t" | "ok" | "bad" | "warn" = "t") {
  const line = el("div");
  const time = new Date().toLocaleTimeString(getLang() === "zh" ? "zh-CN" : "en-GB", {
    hour12: false,
  });
  line.append(el("span", "t", `[${time}] `), el("span", cls, text));
  logBox.append(line);
  logBox.scrollTop = logBox.scrollHeight;
}

// ---- JSON / token viewers -------------------------------------------------

function renderJson(v: unknown, depth: number, key?: string): HTMLElement {
  const line = el("div", "jline");
  line.style.paddingLeft = `${depth * 14}px`;
  if (key !== undefined) {
    line.append(el("span", "json-key", JSON.stringify(key) + ": "));
  }
  if (v === null) {
    line.append(el("span", "json-bool", "null"));
  } else if (typeof v === "string") {
    line.append(el("span", "json-str", JSON.stringify(v)));
  } else if (typeof v === "number") {
    line.append(el("span", "json-num", String(v)));
  } else if (typeof v === "boolean") {
    line.append(el("span", "json-bool", String(v)));
  } else if (Array.isArray(v)) {
    if (v.length === 0) {
      line.append(el("span", "muted", "[]"));
      return line;
    }
    line.append(el("span", "muted", "["));
    for (const item of v) line.append(renderJson(item, depth + 1));
    line.append(closeJson(depth, "]"));
  } else if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>);
    if (entries.length === 0) {
      line.append(el("span", "muted", "{}"));
      return line;
    }
    line.append(el("span", "muted", "{"));
    for (const [k, val] of entries) line.append(renderJson(val, depth + 1, k));
    line.append(closeJson(depth, "}"));
  }
  return line;
}

function closeJson(depth: number, ch: string): HTMLElement {
  const line = el("div", "jline");
  line.style.paddingLeft = `${depth * 14}px`;
  line.append(el("span", "muted", ch));
  return line;
}

function jsonView(v: unknown): HTMLElement {
  const pre = el("pre");
  pre.append(renderJson(v, 0));
  return pre;
}

function tokenView(token: string, label: string): HTMLElement {
  const det = el("details");
  det.append(el("summary", undefined, t("tk.expand", { label })));
  try {
    const { header, payload, parts } = parseCompact(token);
    det.append(
      card(
        [
          el("p", "muted", t("tk.header")),
          jsonView(header),
          el("p", "muted", t("tk.payload")),
          jsonView(payload),
          el("p", "muted", t("tk.sig")),
          el("pre", undefined, parts[2]),
        ],
        label,
      ),
    );
  } catch {
    det.append(card([el("p", "bad", t("tk.damaged"))], label));
  }
  return det;
}

// ---- report viewer --------------------------------------------------------

function reportView(report: VerifyReport): HTMLElement {
  const wrap = el("div");
  const verdict = el("div", "row");
  verdict.append(
    el("span", `pill ${report.permit ? "ok" : "bad"}`, report.permit ? t("r.permit") : t("r.deny")),
  );
  if (report.decision) {
    const notes = report.decision.notes.length
      ? t("r.notes", { n: report.decision.notes.join("; ") })
      : t("r.noNotes");
    verdict.append(
      el(
        "span",
        "muted",
        t("r.decision", {
          p: report.decision.principal,
          a: report.decision.actor,
          c: report.decision.capabilities
            .map((cap) => `${cap.scheme}:${cap.id}`)
            .join(", "),
          n: notes,
        }),
      ),
    );
  }
  wrap.append(verdict);
  const scroll = el("div", "tbl-scroll");
  const table = el("table");
  const head = el("tr");
  for (const h of [t("r.colStep"), t("r.colCheck"), t("r.colResult")]) {
    head.append(el("th", undefined, h));
  }
  table.append(head);
  for (const s of report.steps) {
    const tr = el("tr");
    tr.append(el("td", undefined, String(s.n)));
    tr.append(el("td", undefined, t(`vstep.${s.n}`)));
    const pillTd = el("td");
    const cls = s.status === "ok" ? "ok" : s.status === "fail" ? "bad" : "warn";
    const label =
      s.status === "ok" ? t("r.ok") : s.status === "fail" ? t("r.reject") : t("r.skip");
    pillTd.append(el("span", `pill ${cls}`, label));
    tr.append(pillTd);
    table.append(tr);
    if (s.detail) {
      const tr2 = el("tr");
      const td = el("td");
      td.colSpan = 3;
      td.append(el("span", "muted", t("r.reason", { r: s.detail })));
      tr2.append(td);
      table.append(tr2);
    }
  }
  scroll.append(table);
  wrap.append(scroll);
  if (report.error) wrap.append(el("p", "bad", t("r.denyReason", { r: report.error })));
  return wrap;
}

// ---- kv card ---------------------------------------------------------------

function kvCard(pairs: Array<[string, string]>): HTMLElement {
  const dl = el("dl", "kv");
  for (const [k, v] of pairs) {
    dl.append(el("dt", undefined, k), el("dd", undefined, v));
  }
  return card([dl]);
}

// ---- page header / footer ---------------------------------------------------

function fillHeaderFooter() {
  const title = document.querySelector("#app-title") as HTMLElement | null;
  const tag = document.querySelector("#app-tag") as HTMLElement | null;
  const sub = document.querySelector("#app-subtitle") as HTMLElement | null;
  const footer = document.querySelector("#app-footer") as HTMLElement | null;
  if (title) title.textContent = t("app.title");
  if (tag) tag.textContent = t("app.tag");
  if (sub) sub.textContent = t("app.subtitle");
  if (footer) {
    footer.replaceChildren();
    footer.append(el("span", undefined, t("app.footer.p1")));
    const draftLink = (label: string, href: string) => {
      const a = el("a", undefined, label);
      a.href = href;
      a.target = "_blank";
      a.rel = "noreferrer";
      return a;
    };
    footer.append(
      draftLink("draft-wei-aic-jwt", "https://datatracker.ietf.org/doc/draft-wei-aic-jwt/"),
      el("span", undefined, " · "),
      draftLink("draft-wei-aic-identity-cert", "https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/"),
      el("span", undefined, t("app.footer.p2")),
    );
  }
}

function switchLang(l: Lang) {
  if (l === getLang()) return;
  // Two static pages: index.html is the default (English),
  // index.zh.html is the Chinese version.
  const url = new URL(location.href);
  const parts = url.pathname.split("/");
  parts[parts.length - 1] = l === "en" ? "index.html" : "index.zh.html";
  url.pathname = parts.join("/");
  url.searchParams.delete("lang");
  location.href = url.toString();
}

function langSwitchRow(): HTMLElement {
  const zhBtn = btn("中文", () => switchLang("zh"));
  const enBtn = btn("English", () => switchLang("en"));
  if (getLang() === "zh") zhBtn.classList.add("primary");
  else enBtn.classList.add("primary");
  return row(el("label", undefined, t("ctrl.lang")), zhBtn, enBtn);
}

// ---- panels (rebuilt by init) ----------------------------------------------

let out1: HTMLElement;
let out2: HTMLElement;
let out3: HTMLElement;
let out4: HTMLElement;
let out5: HTMLElement;
let outRefuse: HTMLElement;
let outArtifacts: HTMLElement;
let outScenarioDesc: HTMLElement;

function init() {
  app.replaceChildren();
  logBox.replaceChildren();
  out1 = el("div");
  out2 = el("div");
  out3 = el("div");
  out4 = el("div");
  out5 = el("div");
  outRefuse = el("div");
  outArtifacts = el("div");
  outScenarioDesc = el("p", "muted", t("scenario.happy.desc"));
  fillHeaderFooter();

  const controls = panel(t("ctrl.title"), null, [
    el("p", "subtitle", t("ctrl.sub")),
    row(
      btn(t("ctrl.auto"), () => void autoRun(), { primary: true, id: "btn-auto" }),
      btn(t("ctrl.reset"), () => location.reload()),
    ),
    langSwitchRow(),
  ]);

  const step1 = panel(t("s1.title"), 1, [
    el("p", "subtitle", t("s1.sub")),
    row(btn(t("s1.btn"), () => void step1run(), { id: "btn1" })),
    out1,
  ]);
  const step2 = panel(t("s2.title"), 2, [
    el("p", "subtitle", t("s2.sub")),
    row(btn(t("s2.btn"), () => void step2run(), { id: "btn2" })),
    out2,
  ]);
  const step3 = panel(t("s3.title"), 3, [
    el("p", "subtitle", t("s3.sub")),
    row(btn(t("s3.btn"), () => void step3run(), { id: "btn3" })),
    out3,
  ]);
  const step4 = panel(t("s4.title"), 4, [
    el("p", "subtitle", t("s4.sub")),
    row(
      btn(t("s4.btn"), () => void step4run(), { id: "btn4" }),
      btn(t("s4.refuseBtn"), () => void refuseRun(), { danger: true, id: "btn-refuse" }),
    ),
    outRefuse,
    out4,
  ]);

  const scenarioSelect = el("select");
  scenarioSelect.id = "scenario";
  for (const id of Object.keys(SCENARIO_META) as ScenarioId[]) {
    const opt = el("option");
    opt.value = id;
    opt.textContent = t(`scenario.${id}.title`);
    scenarioSelect.append(opt);
  }
  scenarioSelect.addEventListener("change", () => {
    outScenarioDesc.textContent = t(`scenario.${scenarioSelect.value}.desc`);
  });
  const step5 = panel(t("s5.title"), 5, [
    el("p", "subtitle", t("s5.sub")),
    row(
      el("label", undefined, t("s5.scenarioLabel")),
      scenarioSelect,
      btn(t("s5.btn"), () => void verifyRun(), { primary: true, id: "btn-verify" }),
    ),
    outScenarioDesc,
    out5,
  ]);

  const flowList = el("ol", "flow");
  flowList.style.paddingLeft = "20px";
  for (let i = 1; i <= 4; i++) {
    const li = el("li");
    li.append(
      el("b", undefined, `${t(`flow.${i}.t`)}${t("colon")}`),
      el("span", undefined, t(`flow.${i}.d`)),
    );
    flowList.append(li);
  }
  const flowPanel = panel(t("flow.title"), null, [flowList]);
  const artifactPanel = panel(t("art.title"), null, [
    el("p", "subtitle", t("art.sub")),
    outArtifacts,
  ]);
  const logPanel = panel(t("log.title"), null, [logBox]);

  const left = el("div");
  left.append(controls, step1, step2, step3, step4, step5);
  const right = el("div");
  right.append(flowPanel, artifactPanel, logPanel);
  techSection = buildTechSection(liveValues);
  app.append(left, right, techSection);
  enableStepButtons();
}

// ---- step implementations ---------------------------------------------------

async function step1run() {
  const b = document.getElementById("btn1") as HTMLButtonElement;
  b.disabled = true;
  log(t("s1.log"));
  ui.human = await createHumanIdentity({ now: ui.now });
  await verifyHumanCertificate(ui.human.certificate, ui.human.keyPair.publicKey);
  log(t("s1.logOk"), "ok");
  out1.append(
    kvCard([
      ["realm", ui.human.realm],
      ["id", ui.human.id],
      [t("kv.displayName"), ui.human.displayName],
      [t("kv.kid"), ui.human.kid],
      [t("kv.keyHash"), ui.human.claims.principal.key_hash],
      [t("kv.hashAlg"), ui.human.claims.principal.hash_alg],
    ]),
    card([el("p", "muted", t("s1.claimsTitle")), jsonView(ui.human.claims)], t("s1.cardTitle")),
    tokenView(ui.human.certificate, t("s1.tokenLabel")),
  );
  markStep(1, true);
  enableStepButtons();
  updateArtifacts();
}

async function step2run() {
  const b = document.getElementById("btn2") as HTMLButtonElement;
  b.disabled = true;
  log(t("s2.log"));
  ui.agent = await createAgentIdentity();
  ui.request = buildDelegationRequest({
    agent: ui.agent,
    capabilities: AGENT_CAPS,
    now: ui.now,
  });
  out2.append(
    kvCard([
      ["agent_id", ui.agent.id],
      [t("kv.displayName"), ui.agent.displayName],
      [
        t("s2.caps"),
        AGENT_CAPS.map(
          (c) =>
            `${c.scheme}:${c.id} (max_rows=${(c.params as { max_rows?: number }).max_rows})`,
        ).join(", "),
      ],
      [t("s2.lifetime"), `${ui.request.requestedLifetime}s`],
      [t("s2.nonce"), ui.request.nonce],
      [t("s2.reason"), `${ui.request.reason.code} · ${ui.request.reason.desc}`],
    ]),
    card([jsonView(ui.request)], t("s2.cardTitle")),
  );
  markStep(2, true);
  enableStepButtons();
}

async function step3run() {
  const b = document.getElementById("btn3") as HTMLButtonElement;
  b.disabled = true;
  const human = ui.human as HumanIdentity;
  const req = ui.request as DelegationRequest;
  const subset = capsWithinGrants(human.claims.grants, req.capabilities);
  log(subset.ok ? t("s3.logOk") : t("s3.logWarn"), subset.ok ? "ok" : "warn");
  ui.da = await approveDelegation(human, req, {
    constraints: CONSTRAINTS,
    now: ui.now,
  });
  out3.append(
    row(
      el(
        "span",
        `pill ${subset.ok ? "ok" : "bad"}`,
        subset.ok ? t("s3.pillOk") : t("s3.pillWarn"),
      ),
    ),
    card([el("p", "muted", t("s3.claimsTitle")), jsonView(ui.da.claims)], t("s3.cardTitle")),
    tokenView(ui.da.token, t("s3.tokenLabel")),
  );
  markStep(3, true);
  enableStepButtons();
}

async function step4run() {
  const b = document.getElementById("btn4") as HTMLButtonElement;
  b.disabled = true;
  log(t("s4.log"));
  ui.ca = await createDemoCA();
  ui.certificate = await issueAgentCertificate({
    ca: ui.ca,
    human: ui.human as HumanIdentity,
    agent: ui.agent as AgentIdentity,
    da: ui.da as DAApproval,
    now: ui.now,
  });
  log(t("s4.logOk"), "ok");
  out4.append(
    card([el("p", "muted", t("s4.claimsTitle")), jsonView(ui.certificate.claims)], t("s4.cardTitle")),
    tokenView(ui.certificate.token, t("s4.tokenLabel")),
  );
  markStep(4, true);
  enableStepButtons();
  updateArtifacts();
}

async function refuseRun() {
  const world = assembleWorld();
  outRefuse.replaceChildren();
  log(t("refuse.log"));
  const r = await demonstrateOutOfScopeIssuance(world);
  const pill = el(
    "span",
    `pill ${r.rejected ? "bad" : "ok"}`,
    r.rejected ? t("refuse.pillReject") : t("refuse.pillUnexpected"),
  );
  outRefuse.append(
    card(
      [
        row(pill),
        el(
          "p",
          "muted",
          `${t("refuse.request")}：${r.request.map((c) => `${c.scheme}:${c.id}`).join(", ")}`,
        ),
        el("p", r.rejected ? "bad" : "ok", r.reason),
      ],
      t("refuse.title"),
    ),
  );
  log(
    r.rejected ? t("refuse.logResult") : t("refuse.logUnexpected"),
    r.rejected ? "bad" : "ok",
  );
}

async function verifyRun() {
  const id = (document.getElementById("scenario") as HTMLSelectElement)
    .value as ScenarioId;
  const world = assembleWorld();
  log(t("s5.log", { title: t(`scenario.${id}.title`) }));
  const result = await runScenario(world, id);
  lastScenario = id;
  lastReport = result.report;
  const c = card(
    [
      el("p", "subtitle", `${t(`scenario.${id}.title`)}：${t(`scenario.${id}.desc`)}`),
      ...(result.report ? [reportView(result.report)] : []),
    ],
    t("s5.cardTitle"),
  );
  out5.replaceChildren(c);
  log(result.report?.permit ? t("r.verdict") : t("r.verdictDeny"), result.report?.permit ? "ok" : "bad");
  refreshTech();
}

// ---- helpers for state & navigation -----------------------------------------

function assembleWorld(): DemoWorld {
  if (!ui.human || !ui.agent || !ui.ca || !ui.da || !ui.certificate) {
    throw new Error(t("err.prereq"));
  }
  return {
    human: ui.human,
    agent: ui.agent,
    ca: ui.ca,
    da: ui.da,
    certificate: ui.certificate,
    constraints: CONSTRAINTS,
    verifierBase: buildVerifierBase({
      human: ui.human,
      agent: ui.agent,
      ca: ui.ca,
      now: ui.now,
    }),
    now: ui.now,
  };
}

function markStep(no: number, done: boolean, fail = false) {
  const target = document.querySelector(
    `section.panel[data-step="${no}"]`,
  ) as HTMLElement | null;
  const badge = target?.querySelector(".step-no") as HTMLElement | null;
  if (badge) {
    badge.classList.toggle("done", done);
    badge.classList.toggle("fail", fail);
  }
}

function enableStepButtons() {
  const has = (x: unknown) => x !== undefined;
  const get = (id: string) => document.getElementById(id) as HTMLButtonElement;
  get("btn1").disabled = has(ui.human);
  get("btn2").disabled = !has(ui.human) || has(ui.agent);
  get("btn3").disabled = !has(ui.agent) || has(ui.da);
  get("btn4").disabled = !has(ui.da) || has(ui.certificate);
  get("btn-verify").disabled = !has(ui.certificate);
  get("btn-refuse").disabled = !has(ui.certificate);
  refreshTech();
}

function updateArtifacts() {
  const nodes: HTMLElement[] = [];
  if (ui.human) {
    nodes.push(
      el("p", "muted", t("art.humanLine")),
      tokenView(ui.human.certificate, t("art.humanLabel")),
    );
  }
  if (ui.da) {
    nodes.push(el("p", "muted", t("art.daLine")), tokenView(ui.da.token, t("art.daLabel")));
  }
  if (ui.certificate) {
    nodes.push(
      el("p", "muted", t("art.certLine")),
      tokenView(ui.certificate.token, t("art.certLabel")),
    );
  }
  outArtifacts.replaceChildren(...nodes);
}

function liveValues(): LiveValues {
  return {
    humanKid: ui.human?.kid,
    humanKeyHash: ui.human?.claims.principal.key_hash,
    agentId: ui.agent?.id,
    caIssuer: ui.ca?.issuer,
    caKid: ui.ca?.kid,
    agentJkt: ui.certificate?.claims.cnf.jkt,
    daNonce: ui.da?.claims.nonce,
    agentCaps: ui.certificate?.claims.aic.capabilities
      .map((c) => `${c.scheme}:${c.id}`)
      .join(", "),
    lastReport,
  };
}

function refreshTech() {
  const fresh = buildTechSection(liveValues);
  techSection.replaceWith(fresh);
  techSection = fresh;
}

async function autoRun() {
  init();
  for (const id of ["btn1", "btn2", "btn3", "btn4", "btn-verify", "btn-refuse"]) {
    (document.getElementById(id) as HTMLButtonElement).disabled = true;
  }
  await step1run();
  await sleep(300);
  await step2run();
  await sleep(300);
  await step3run();
  await sleep(300);
  await step4run();
  await sleep(300);
  const autoScenario = new URLSearchParams(location.search).get("auto");
  (document.getElementById("scenario") as HTMLSelectElement).value =
    autoScenario && autoScenario in SCENARIO_META ? autoScenario : "happy";
  await verifyRun();
  log(t("auto.done"), "ok");
}

init();

// Optional: open with ?auto to run the full demo automatically.
if (new URLSearchParams(location.search).has("auto")) {
  setTimeout(() => void autoRun(), 250);
}
