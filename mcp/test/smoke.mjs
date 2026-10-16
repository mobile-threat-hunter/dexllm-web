// Smoke test: spawns the real server over stdio via the SDK client and runs
// the plan's checklist against a known test APK. The SDK client itself is the
// stdout-cleanliness gate — any non-JSON-RPC byte on stdout breaks framing.
//   node test/smoke.mjs [apk-path]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const APK = process.argv[2] || "/home/nyahumi/Project/dexllm/test_apk/APK/a2dp.Vol_137.apk";
const SERVER = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "server.mjs");

let fails = 0;
const check = (name, ok, extra) => {
  console.log((ok ? "PASS" : "FAIL") + "  " + name + (ok || !extra ? "" : "  [" + extra + "]"));
  if (!ok) fails++;
};
const parse = (r) => JSON.parse(r.content[0].text);

const client = new Client({ name: "dexllm-smoke", version: "0.0.1" });
await client.connect(new StdioClientTransport({
  command: process.execPath,
  args: [SERVER],
  stderr: "inherit",
}));

try {
  // tool inventory
  const tools = (await client.listTools()).tools.map(t => t.name).sort();
  check("tool count = 14", tools.length === 14, tools.join(","));
  check("dex-only disclaimer present", (await client.listTools()).tools
    .filter(t => ["components", "permissions", "iocs", "capabilities"].includes(t.name))
    .every(t => /manifest/i.test(t.description)));

  // guard before load
  const pre = await client.callTool({ name: "iocs", arguments: {} });
  check("pre-load iocs isError + guidance", pre.isError === true &&
    pre.content[0].text.includes("load_apk"), pre.content[0].text);

  // load_apk
  const load = parse(await client.callTool({ name: "load_apk", arguments: { path: APK } }));
  check("load_apk dexCount>=1 classCount>0", load.dexCount >= 1 && load.classCount > 0,
    JSON.stringify(load));

  // list_classes: prefix + pagination
  const lc = parse(await client.callTool({
    name: "list_classes", arguments: { package_prefix: "La2dp/", limit: 500 },
  }));
  const names = lc.classes.map(c => typeof c === "string" ? c : c.desc);
  check("list_classes all match prefix", lc.count > 0 && names.every(c => c.startsWith("La2dp/")),
    "count=" + lc.count);
  const lcEnd = parse(await client.callTool({
    name: "list_classes", arguments: { package_prefix: "La2dp/", offset: lc.total },
  }));
  check("list_classes offset=total -> 0 rows", lcEnd.count === 0);

  // decompile_class: window semantics
  const CLS = "La2dp/Vol/AppChooser;";
  const d1raw = (await client.callTool({
    name: "decompile_class", arguments: { class_desc: CLS, max_lines: 10 },
  })).content[0].text;
  const d1meta = JSON.parse(d1raw.split("\n")[0]);
  check("decompile totalLines>0 + 'class' in window",
    d1meta.totalLines > 0 && d1raw.includes("class"), d1raw.slice(0, 120));
  const d2raw = (await client.callTool({
    name: "decompile_class", arguments: { class_desc: CLS, start_line: 5, max_lines: 10 },
  })).content[0].text;
  const d2meta = JSON.parse(d2raw.split("\n")[0]);
  check("decompile window moves", d2meta.window.start === 5 &&
    d2raw.split("\n").slice(1).length === 10, JSON.stringify(d2meta.window));
  // dotted-FQN input resolves too
  const d3meta = JSON.parse((await client.callTool({
    name: "decompile_class", arguments: { class_desc: "a2dp.Vol.AppChooser", max_lines: 1 },
  })).content[0].text.split("\n")[0]);
  check("decompile accepts dotted FQN", d3meta.class === CLS);

  // search_symbols string + usages round-trip
  const ss = parse(await client.callTool({
    name: "search_symbols", arguments: { query: "http", kind: "string", limit: 5 },
  }));
  check("search_symbols cap + truncated flag", ss.count <= 5 && typeof ss.truncated === "boolean",
    JSON.stringify({ count: ss.count, truncated: ss.truncated }));
  if (ss.results.length) {
    const us = parse(await client.callTool({
      name: "usages_of_string", arguments: { value: ss.results[0] },
    }));
    check("usages_of_string round-trip", Array.isArray(us.methods),
      "total=" + us.total);
  } else check("usages_of_string round-trip", false, "no http string found");

  // callers_of_method via a method search hit
  const ms = parse(await client.callTool({
    name: "search_symbols", arguments: { query: "AppChooser;->onCreate", kind: "method", limit: 1 },
  }));
  if (ms.results.length) {
    const md = typeof ms.results[0] === "string" ? ms.results[0] : ms.results[0].desc;
    const xr = parse(await client.callTool({
      name: "callers_of_method", arguments: { method_desc: md },
    }));
    check("callers_of_method shape", Array.isArray(xr.callSites) &&
      xr.callSites.every(s => typeof s.offset === "number"), "total=" + xr.total);
  } else check("callers_of_method shape", false, "no method hit");

  // java-form query bridges to smali descriptors
  const jf = parse(await client.callTool({
    name: "search_symbols", arguments: { query: "a2dp.Vol.AppChooser.onCreate", kind: "method", limit: 5 },
  }));
  check("search_symbols java-form query", Array.isArray(jf.results) && jf.results.some(r =>
    (typeof r === "string" ? r : r.desc).startsWith("La2dp/Vol/AppChooser;->onCreate")),
    JSON.stringify(jf.results));

  // bare `->` query still reaches smali descriptors (candidates are normalized)
  const bq = parse(await client.callTool({
    name: "search_symbols", arguments: { query: "AppChooser->onCreate", kind: "method", limit: 5 },
  }));
  check("search_symbols bare-arrow query", Array.isArray(bq.results) && bq.results.length > 0,
    "count=" + bq.count);

  // string search stays literal: "://" must hit real URLs, and its normalized
  // form (":.") must not be what matched
  const sl = parse(await client.callTool({
    name: "search_symbols", arguments: { query: "://", kind: "string", limit: 5 },
  }));
  check("string search stays literal", Array.isArray(sl.results) &&
    sl.results.length > 0 && sl.results.every(s => s.includes("://")),
    "count=" + sl.count);

  // accessors_of_field + references_to_type shapes
  const fsr = parse(await client.callTool({
    name: "search_symbols", arguments: { query: "La2dp/", kind: "field", limit: 1 },
  }));
  if (fsr.results.length) {
    const fd = typeof fsr.results[0] === "string" ? fsr.results[0] : fsr.results[0].desc;
    const ac = parse(await client.callTool({
      name: "accessors_of_field", arguments: { field_desc: fd },
    }));
    check("accessors_of_field shape", Array.isArray(ac.getters) && Array.isArray(ac.putters));
  } else check("accessors_of_field shape", false, "no field hit");
  const tr = parse(await client.callTool({
    name: "references_to_type", arguments: { class_desc: CLS },
  }));
  check("references_to_type buckets", ["fields", "methodsReturning", "methodsWithParam"]
    .every(k => Array.isArray(tr[k])));

  // panels: iocs / capabilities / permissions / components
  const io = parse(await client.callTool({ name: "iocs", arguments: {} }));
  check("iocs shape", Array.isArray(io.network) && Array.isArray(io.providers),
    "network=" + io.network.length + " providers=" + io.providers.length);

  const caps = parse(await client.callTool({ name: "capabilities", arguments: {} }));
  check("capabilities catalogVersion + matchedApis>0",
    !!caps.catalogVersion && caps.matchedApis > 0,
    "v=" + caps.catalogVersion + " matched=" + caps.matchedApis);
  const sorted = caps.apiHits.every((h, i, a) => !i || a[i - 1].callSiteCount >= h.callSiteCount);
  check("capabilities apiHits sorted desc", sorted);

  const pm = parse(await client.callTool({ name: "permissions", arguments: {} }));
  const BUCKETS = new Set(["dangerous", "signature", "internal", "normal", "other"]);
  check("permissions buckets valid + callers<=20",
    pm.rows.length > 0 && pm.rows.every(r => BUCKETS.has(r.level) && r.callers.length <= 20),
    "rows=" + pm.rows.length);

  const comp = parse(await client.callTool({ name: "components", arguments: {} }));
  const KINDS = new Set(["device-admin", "accessibility", "notif-listener", "vpn", "job",
    "application", "provider", "receiver", "service", "activity"]);
  check("components kinds valid", comp.groups.length > 0 &&
    comp.groups.every(g => KINDS.has(g.kind) && g.classes.length === g.count),
    comp.groups.map(g => g.kind + ":" + g.count).join(" "));

  // load_renames: display reflection in list/decompile/search
  const rnPath = path.join(os.tmpdir(), "_dexllm_mcp_smoke_renames.json");
  fs.writeFileSync(rnPath, JSON.stringify({
    classes: { [CLS]: "ZzSmokeRenamed" },
    methods: { [CLS + "->onCreate"]: "zzSmokeOnCreate" },
    fields: {},
  }));
  const rn = parse(await client.callTool({ name: "load_renames", arguments: { path: rnPath } }));
  check("load_renames counts", rn.total === 2, JSON.stringify(rn));
  // inner classes ($1…) sort before "AppChooser;" so the limit must cover them
  const lc2 = parse(await client.callTool({
    name: "list_classes", arguments: { package_prefix: "La2dp/Vol/AppChooser", limit: 20 },
  }));
  check("list_classes shows display pair", lc2.classes.some(c =>
    typeof c === "object" && c.desc === CLS && c.display.includes("ZzSmokeRenamed")),
    JSON.stringify(lc2.classes));
  const d4 = (await client.callTool({
    name: "decompile_class", arguments: { class_desc: CLS, max_lines: 2000 },
  })).content[0].text;
  check("decompile applies renames", d4.includes("ZzSmokeRenamed") && d4.includes("zzSmokeOnCreate"));
  const ss2 = parse(await client.callTool({
    name: "search_symbols", arguments: { query: "zzsmokerenamed", kind: "class" },
  }));
  check("search matches display name", ss2.count >= 1, JSON.stringify(ss2.results));
  fs.rmSync(rnPath, { force: true });

  // add_dump: same APK as a dump source
  const ad = parse(await client.callTool({ name: "add_dump", arguments: { path: APK, label: "smoke-dump" } }));
  check("add_dump dexCount grows", ad.dexCount > load.dexCount && ad.sources === 2,
    JSON.stringify(ad));
  const lc3 = parse(await client.callTool({ name: "list_classes", arguments: { limit: 1 } }));
  check("post-dump query works", lc3.total > 0);
  // the dump duplicates every class, so the ORIGINAL's call sites are shadowed
  // (dump-first resolution) while the dump's copies are live — both must appear
  const sx = parse(await client.callTool({
    name: "callers_of_method",
    arguments: { method_desc: "La2dp/Vol/AppChooser$AppInfoCache;->getAppName()Ljava/lang/String;" },
  }));
  check("per-site shadowed flag in dump session",
    Array.isArray(sx.callSites) && sx.callSites.some(s => s.shadowed === true) &&
    sx.callSites.some(s => !s.shadowed),
    "sites=" + sx.total);

  // reload resets everything
  const re = parse(await client.callTool({ name: "load_apk", arguments: { path: APK } }));
  check("reload resets (dexCount back, renames cleared)", re.dexCount === load.dexCount);
  const lc4 = parse(await client.callTool({
    name: "list_classes", arguments: { package_prefix: "La2dp/Vol/AppChooser", limit: 20 },
  }));
  check("renames gone after reload", lc4.classes.every(c => typeof c === "string"));
} finally {
  await client.close();
}

console.log(fails ? "\nSMOKE: " + fails + " FAILURE(S)" : "\nSMOKE: all passed");
process.exit(fails ? 1 : 0);
