// Technical deep-dive panels for the demo UI: trust model, nested
// token structure, claims reference, validation pipeline, capability
// matching and security notes. All strings are localized via i18n.
import type { VerifyReport } from "../lib/types.ts";
import { t } from "../lib/i18n.ts";

export interface LiveValues {
  humanKid?: string;
  humanKeyHash?: string;
  agentId?: string;
  caIssuer?: string;
  caKid?: string;
  agentJkt?: string;
  daNonce?: string;
  agentCaps?: string;
  lastReport?: VerifyReport;
}

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

function subPanel(title: string, open: boolean, body: HTMLElement[]): HTMLElement {
  const det = el("details", "tech");
  det.open = open;
  det.append(el("summary", undefined, title));
  for (const node of body) det.append(node);
  return det;
}

function chainNode(title: string, subtitle: string): HTMLElement {
  const n = el("div", "node");
  n.append(el("b", undefined, title), el("span", undefined, subtitle));
  return n;
}

function chainArrow(label: string): HTMLElement {
  const a = el("div", "arrow");
  a.append(el("span", undefined, "→"), el("small", undefined, label));
  return a;
}

function live(v: string | undefined, fallback: string): string {
  return v && v.length ? v : fallback;
}

// ---- 1. trust model & signature chain -------------------------------------

function trustPanel(getLive: () => LiveValues): HTMLElement {
  const v = getLive();
  const chain = el("div", "chain");
  chain.append(
    chainNode(t("t1.nodeHuman"), t("t1.nodeHumanSub")),
    chainArrow(t("t1.arrow1")),
    chainNode(t("t1.nodeDA"), t("t1.nodeDASub", { kid: live(v.humanKid, "human-…") })),
    chainArrow(t("t1.arrow2")),
    chainNode(t("t1.nodeCA"), t("t1.nodeCASub")),
    chainArrow(t("t1.arrow3")),
    chainNode(t("t1.nodeOuter"), t("t1.nodeOuterSub", { kid: live(v.caKid, "ca-…") })),
    chainArrow(t("t1.arrow4")),
    chainNode(t("t1.nodeGW"), t("t1.nodeGWSub")),
  );
  const bind = el("table");
  const head = el("tr");
  for (const h of [t("t1.hCol"), t("t1.bCol"), t("t1.pCol")]) head.append(el("th", undefined, h));
  bind.append(head);
  const rows: Array<[string, string, string]> = [
    [t("t1.r1a"), t("t1.r1b"), t("t1.r1c")],
    [t("t1.r2a"), t("t1.r2b"), t("t1.r2c")],
    [t("t1.r3a"), t("t1.r3b"), t("t1.r3c")],
  ];
  for (const [a, b, c] of rows) {
    const tr = el("tr");
    tr.append(el("td", undefined, a), el("td", undefined, b), el("td", undefined, c));
    bind.append(tr);
  }
  return subPanel(t("t1.title"), true, [
    el("p", "subtitle", t("t1.sub")),
    chain,
    el("p", "muted", t("t1.bindTitle")),
    bind,
  ]);
}

// ---- 2. nested token structure ---------------------------------------------

function nestingPanel(getLive: () => LiveValues): HTMLElement {
  const v = getLive();
  const outer = el("div", "nest");
  const seg = (title: string, lines: Array<[string, string]>): HTMLElement => {
    const s = el("div", "seg");
    s.append(el("b", undefined, title));
    for (const [k, val] of lines) {
      const row = el("div");
      row.append(el("span", "json-key", k + ": "), el("span", "json-str", val));
      s.append(row);
    }
    return s;
  };
  const daBox = el("div", "seg");
  daBox.append(el("b", undefined, t("t2.segDa")));
  daBox.append(
    seg(t("t2.header"), [
      ["typ", "aic+da+jwt"],
      ["kid", live(v.humanKid, "human-…")],
    ]),
    seg(t("t2.payload"), [
      ["agent_id", live(v.agentId, "agent:…")],
      ["reason", "DATA_ANALYSIS"],
      ["capabilities", live(v.agentCaps, "database:query:SELECT")],
      ["requested_lifetime", "3600s"],
      ["nonce", live(v.daNonce, "32-byte base64url")],
    ]),
  );
  outer.append(
    seg(t("t2.header"), [
      ["typ", "aic+jwt"],
      ["alg", "ES256"],
      ["kid", live(v.caKid, "ca-…")],
    ]),
    seg(t("t2.payload"), [
      ["iss", live(v.caIssuer, "https://ca.example/aic")],
      ["sub", live(v.agentId, "agent:…")],
      ["cnf.jkt", live(v.agentJkt, "agent key thumbprint")],
      ["aic.principal", live(v.humanKeyHash, "human jkt thumbprint").slice(0, 18) + "…"],
      ["aic.delegation_mode", "representative"],
      ["da", t("t2.l7")],
    ]),
    daBox,
    seg(t("t2.signature"), [["CA key", t("t2.sigNote")]]),
  );
  return subPanel(t("t2.title"), true, [
    el("p", "subtitle", t("t2.sub")),
    outer,
    el("p", "muted", t("t2.note")),
  ]);
}

// ---- 3. claims reference -----------------------------------------------------

const CLAIM_ROWS: Array<[string, string, string]> = [
  ["cl.iss.c", "cl.iss.m", "cl.iss.d"],
  ["cl.sub.c", "cl.sub.m", "cl.sub.d"],
  ["cl.aud.c", "cl.aud.m", "cl.aud.d"],
  ["cl.time.c", "cl.time.m", "cl.time.d"],
  ["cl.jti.c", "cl.jti.m", "cl.jti.d"],
  ["cl.cnf.c", "cl.cnf.m", "cl.cnf.d"],
  ["cl.ver.c", "cl.ver.m", "cl.ver.d"],
  ["cl.principal.c", "cl.principal.m", "cl.principal.d"],
  ["cl.mode.c", "cl.mode.m", "cl.mode.d"],
  ["cl.caps.c", "cl.caps.m", "cl.caps.d"],
  ["cl.constr.c", "cl.constr.m", "cl.constr.d"],
  ["cl.depth.c", "cl.depth.m", "cl.depth.d"],
  ["cl.da.c", "cl.da.m", "cl.da.d"],
  ["cl.agent.c", "cl.agent.m", "cl.agent.d"],
  ["cl.reason.c", "cl.reason.m", "cl.reason.d"],
  ["cl.dacaps.c", "cl.dacaps.m", "cl.dacaps.d"],
  ["cl.life.c", "cl.life.m", "cl.life.d"],
  ["cl.nonce.c", "cl.nonce.m", "cl.nonce.d"],
  ["cl.grants.c", "cl.grants.m", "cl.grants.d"],
  ["cl.policy.c", "cl.policy.m", "cl.policy.d"],
];

function claimsPanel(): HTMLElement {
  const table = el("table");
  const head = el("tr");
  for (const h of [t("t3.h1"), t("t3.h2"), t("t3.h3")]) head.append(el("th", undefined, h));
  table.append(head);
  const section = (name: string) => {
    const tr = el("tr");
    const td = el("td");
    td.colSpan = 3;
    td.append(el("b", undefined, name));
    tr.append(td);
    table.append(tr);
  };
  section(t("t3.secOuter"));
  for (const row of CLAIM_ROWS.slice(0, 13)) {
    const [ck, mk, dk] = row;
    const tr = el("tr");
    tr.append(el("td", undefined, t(ck)), el("td", undefined, t(mk)), el("td", undefined, t(dk)));
    table.append(tr);
  }
  section(t("t3.secDa"));
  for (const row of CLAIM_ROWS.slice(13, 18)) {
    const [ck, mk, dk] = row;
    const tr = el("tr");
    tr.append(el("td", undefined, t(ck)), el("td", undefined, t(mk)), el("td", undefined, t(dk)));
    table.append(tr);
  }
  section(t("t3.secPa"));
  for (const row of CLAIM_ROWS.slice(18)) {
    const [ck, mk, dk] = row;
    const tr = el("tr");
    tr.append(el("td", undefined, t(ck)), el("td", undefined, t(mk)), el("td", undefined, t(dk)));
    table.append(tr);
  }
  const scroll = el("div", "tbl-scroll");
  scroll.append(table);
  return subPanel(t("t3.title"), false, [
    el("p", "subtitle", t("t3.sub")),
    scroll,
  ]);
}

// ---- 4. validation pipeline walkthrough --------------------------------------

function pipelinePanel(getLive: () => LiveValues): HTMLElement {
  const list = el("div");
  for (let n = 1; n <= 13; n++) {
    const det = el("details", "tech");
    det.append(el("summary", undefined, t("t4.stepPrefix", { n, title: t(`pipe.${n}.title`) })));
    const body = el("div", "card");
    body.append(
      el("p", undefined, t("t4.do", { d: t(`pipe.${n}.how`) })),
      el("p", "muted", t("t4.fail", { f: t(`pipe.${n}.fail`) })),
    );
    det.append(body);
    list.append(det);
  }
  const liveReport = getLive().lastReport;
  let lastLine: string;
  if (!liveReport) {
    lastLine = t("t4.lastNone");
  } else if (liveReport.permit) {
    lastLine = t("t4.lastOk");
  } else {
    lastLine = t("t4.lastDeny", {
      n: liveReport.steps.find((s) => s.status === "fail")?.n ?? "-",
    });
  }
  return subPanel(t("t4.title"), true, [
    el("p", "subtitle", t("t4.sub")),
    list,
    el("p", "muted", lastLine),
  ]);
}

// ---- 5. capability matching --------------------------------------------------

function capabilityPanel(): HTMLElement {
  const table = el("table");
  const head = el("tr");
  for (const h of [t("t5.h1"), t("t5.h2"), t("t5.h3"), t("t5.h4")]) head.append(el("th", undefined, h));
  table.append(head);
  const rows: Array<[string, string, string, string, boolean]> = [
    ["t5.r1a", "t5.r1b", "t5.r1c", "t5.r1d", true],
    ["t5.r2a", "t5.r2b", "t5.r2c", "t5.r2d", false],
    ["t5.r3a", "t5.r3b", "t5.r3c", "t5.r3d", false],
    ["t5.r4a", "t5.r4b", "t5.r4c", "t5.r4d", false],
  ];
  for (const [a, b, c, d, allow] of rows) {
    const tr = el("tr");
    const pill = el("td");
    pill.append(el("span", `pill ${allow ? "ok" : "bad"}`, t(c)));
    tr.append(el("td", undefined, t(a)), el("td", undefined, t(b)), pill, el("td", undefined, t(d)));
    table.append(tr);
  }
  return subPanel(t("t5.title"), false, [
    el("p", "subtitle", t("t5.sub")),
    table,
    el("p", "muted", t("t5.note")),
  ]);
}

// ---- 6. constraints & security notes ------------------------------------------

function securityPanel(): HTMLElement {
  const items: Array<[string, string]> = [
    [t("t6.sec1.t"), t("t6.sec1.d")],
    [t("t6.sec2.t"), t("t6.sec2.d")],
    [t("t6.sec3.t"), t("t6.sec3.d")],
    [t("t6.sec4.t"), t("t6.sec4.d")],
    [t("t6.sec5.t"), t("t6.sec5.d")],
  ];
  const list = el("ul", "flow");
  for (const [k, v] of items) {
    const li = el("li");
    li.append(el("b", undefined, `${k}${t("colon")}`), el("span", undefined, v));
    list.append(li);
  }
  const constraintRow = el("div", "card");
  constraintRow.append(
    el("p", "muted", t("t6.cardTitle")),
    el("pre", undefined, `{ "scheme": "varwof/constraint-v1", "id": "max-concurrent", "params": { "max": 5 } }`),
    el("p", "muted", t("t6.cardBody")),
  );
  return subPanel(t("t6.title"), false, [constraintRow, list]);
}

// ---- entry --------------------------------------------------------------------

export function buildTechSection(getLive: () => LiveValues): HTMLElement {
  const section = el("section", "panel");
  section.style.gridColumn = "1 / -1";
  section.append(
    el("h2", undefined, t("tech.title")),
    el("p", "subtitle", t("tech.sub")),
    trustPanel(getLive),
    nestingPanel(getLive),
    claimsPanel(),
    pipelinePanel(getLive),
    capabilityPanel(),
    securityPanel(),
  );
  return section;
}
