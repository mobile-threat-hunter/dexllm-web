#!/usr/bin/env node
// dexllm MCP server — stdio transport over the dexllm-web wasm engine.
// Register with:  claude mcp add dexllm -- node /path/to/dexllm-web/mcp/server.mjs
//
// Scope note repeated in every tool description: the engine sees dex bytecode
// ONLY (no AndroidManifest.xml), so components/permissions are code-derived
// candidates, not declared facts. One APK per process; load_apk resets all.
import fs from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  ensureEngine, session, requireDk, classList, stringList,
  loadApk, addDump, vecToArray, describeError,
} from "./engine.mjs";
import {
  descToJava, setRenames, clearRenames, renameCount,
  displayClassDesc, displayDesc, origDottedToDesc, applyRenames,
  computePerms, computeComponents, computeCaps,
} from "./ported.mjs";

const DEX_ONLY = " (dex bytecode only — no AndroidManifest access)";
const TEXT_CAP = 200_000;

// ── response helpers ─────────────────────────────────────────────────────────
function textResult(s) {
  if (s.length > TEXT_CAP) {
    s = s.slice(0, TEXT_CAP) +
      "\n…[TRUNCATED: full result was " + s.length +
      " chars — narrow the query with limit/offset/prefix parameters]";
  }
  return { content: [{ type: "text", text: s }] };
}
const jsonResult = (obj) => textResult(JSON.stringify(obj, null, 1));

function wrap(fn) {
  return async (args) => {
    try {
      return await fn(args ?? {});
    } catch (err) {
      return { isError: true, content: [{ type: "text", text: describeError(err) }] };
    }
  };
}

// {desc, display} pairing when renames are loaded, bare string otherwise.
const disp = (d) => {
  const x = displayDesc(d);
  return x !== d ? { desc: d, display: x } : d;
};

// Accept an original descriptor, a display descriptor, or a dotted FQN
// (original or display) and resolve to the original descriptor.
function resolveClassDesc(input) {
  const classes = classList();
  if (classes.includes(input)) return input;
  const dotted = (input.startsWith("L") && input.endsWith(";")) ? descToJava(input) : input;
  const o = origDottedToDesc(dotted);
  if (o && classes.includes(o)) return o;
  const asDesc = "L" + dotted.replace(/\./g, "/") + ";";
  if (classes.includes(asDesc)) return asDesc;
  throw new Error("class not found: " + input);
}

// search_symbols corpora, cached per dk instance (invalidated by load/add_dump
// because those produce a new WasmDexKit object).
let _sym = { dk: null, method: null, field: null };
function symbolCorpus(kind) {
  const dk = requireDk();
  if (_sym.dk !== dk) _sym = { dk, method: null, field: null };
  if (kind === "class") return classList();
  if (kind === "string") return stringList();
  if (kind === "method") {
    if (!_sym.method) _sym.method = vecToArray(dk.listAllMethodDescriptors());
    return _sym.method;
  }
  if (!_sym.field) _sym.field = vecToArray(dk.listAllFieldDescriptors());
  return _sym.field;
}

// ── server + tools ───────────────────────────────────────────────────────────
const server = new McpServer({ name: "dexllm", version: "0.1.0" });

server.registerTool("load_apk", {
  description: "Load an APK/DEX file from a local path into the analysis session. " +
    "Resets everything (previous APK, dumps, renames). Call this first." + DEX_ONLY,
  inputSchema: { path: z.string().describe("absolute path to the .apk/.dex file") },
}, wrap(async ({ path }) => {
  clearRenames();
  const r = await loadApk(path);
  return jsonResult({ ...r, note: "session reset; renames cleared" });
}));

server.registerTool("add_dump", {
  description: "Add a runtime-dumped dex/apk as an extra source. Dumps SHADOW the " +
    "original (ART-mirror semantics): a class redeclared in a dump wins over the " +
    "packed original. Useful for unpacking packed samples." + DEX_ONLY,
  inputSchema: {
    path: z.string().describe("absolute path to the dumped .dex/.apk"),
    label: z.string().optional().describe("display label for this source"),
  },
}, wrap(async ({ path, label }) => jsonResult(await addDump(path, label))));

server.registerTool("load_renames", {
  description: "Load a renames JSON file exported from the dexllm-web UI " +
    '({"classes":{},"methods":{},"fields":{}}). After loading, all tool outputs ' +
    "pair original descriptors with display names, and decompiled code shows " +
    "display names. Replaces any previously loaded renames.",
  inputSchema: { path: z.string().describe("path to the exported renames JSON") },
}, wrap(async ({ path }) => {
  requireDk();
  const o = JSON.parse(fs.readFileSync(path, "utf8"));
  setRenames(o);
  return jsonResult({
    classes: Object.keys(o.classes || {}).length,
    methods: Object.keys(o.methods || {}).length,
    fields: Object.keys(o.fields || {}).length,
    total: renameCount(),
  });
}));

server.registerTool("list_classes", {
  description: "List class descriptors, paginated. Use package_prefix " +
    '(descriptor form, e.g. "Lcom/example/") to narrow. Never dumps the whole ' +
    "corpus at once — iterate with offset." + DEX_ONLY,
  inputSchema: {
    package_prefix: z.string().optional().describe('descriptor prefix filter, e.g. "La2dp/"'),
    offset: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(500).default(200),
  },
}, wrap(async ({ package_prefix, offset = 0, limit = 200 }) => {
  requireDk();
  const all = package_prefix
    ? classList().filter(c => c.startsWith(package_prefix))
    : classList();
  const page = all.slice(offset, offset + limit).map(c => {
    const d = displayClassDesc(c);
    return d !== c ? { desc: c, display: d } : c;
  });
  return jsonResult({ total: all.length, offset, count: page.length, classes: page });
}));

server.registerTool("decompile_class", {
  description: "Decompile one class to Java (DAD decompiler). Accepts an original " +
    'descriptor ("La/b/C;"), dotted FQN, or a renamed display name. Output is ' +
    "windowed — use start_line/max_lines to page through large classes (the " +
    "decompile itself is cached, window moves are free). Display renames applied " +
    "when loaded.",
  inputSchema: {
    class_desc: z.string().describe("class descriptor or dotted FQN"),
    start_line: z.number().int().min(1).default(1),
    max_lines: z.number().int().min(1).max(2000).default(800),
  },
}, wrap(async ({ class_desc, start_line = 1, max_lines = 800 }) => {
  const dk = requireDk();
  const cls = resolveClassDesc(class_desc);
  if (session.decompiled?.cls !== cls) {
    session.decompiled = { cls, text: dk.decompileClassJava(cls) };
  }
  const lines = applyRenames(session.decompiled.text, cls).split("\n");
  const from = Math.min(start_line - 1, Math.max(lines.length - 1, 0));
  const win = lines.slice(from, from + max_lines);
  const meta = {
    class: cls,
    ...(displayClassDesc(cls) !== cls ? { display: displayClassDesc(cls) } : {}),
    totalLines: lines.length,
    window: { start: from + 1, end: from + win.length },
  };
  return textResult(JSON.stringify(meta) + "\n" + win.join("\n"));
}));

server.registerTool("search_symbols", {
  description: "Substring search (case-insensitive) over one symbol kind: class " +
    "descriptors, method descriptors, field descriptors, or string literals. " +
    "When renames are loaded, matches against BOTH original and display names.",
  inputSchema: {
    query: z.string().min(1),
    kind: z.enum(["class", "method", "field", "string"]),
    limit: z.number().int().min(1).max(600).default(200),
  },
}, wrap(async ({ query, kind, limit = 200 }) => {
  requireDk();
  const q = query.toLowerCase();
  const corpus = symbolCorpus(kind);
  const mapped = kind !== "string" && renameCount() > 0;
  const results = [];
  let truncated = false;
  for (const s of corpus) {
    let hit = s.toLowerCase().includes(q);
    let d = null;
    if (!hit && mapped) {
      d = displayDesc(s);
      hit = d !== s && d.toLowerCase().includes(q);
    }
    if (!hit) continue;
    if (results.length >= limit) { truncated = true; break; }
    if (kind === "string") results.push(s);
    else {
      d = d ?? (mapped ? displayDesc(s) : s);
      results.push(d !== s ? { desc: s, display: d } : s);
    }
  }
  return jsonResult({ kind, count: results.length, truncated, results });
}));

server.registerTool("callers_of_method", {
  description: "Cross-references TO a method: every call site invoking the given " +
    'method descriptor ("La/b/C;->name(...)Ret"), with bytecode offsets. Same ' +
    "engine path as the web UI's xref popup.",
  inputSchema: {
    method_desc: z.string().describe("full method descriptor"),
    limit: z.number().int().min(1).max(1000).default(200),
  },
}, wrap(async ({ method_desc, limit = 200 }) => {
  const dk = requireDk();
  const sites = dk.findCallSitesWithOffset(method_desc);
  const out = sites.slice(0, limit).map(s => ({ caller: disp(s.caller), offset: s.offset }));
  return jsonResult({ total: sites.length, truncated: sites.length > limit, callSites: out });
}));

server.registerTool("usages_of_string", {
  description: "Find methods whose bytecode loads the given string literal " +
    "(exact match). Use search_symbols kind=string first to discover values.",
  inputSchema: {
    value: z.string().describe("exact string literal value"),
    limit: z.number().int().min(1).max(1000).default(200),
  },
}, wrap(async ({ value, limit = 200 }) => {
  const dk = requireDk();
  const methods = vecToArray(dk.findMethodsUsingString(value));
  return jsonResult({
    total: methods.length,
    truncated: methods.length > limit,
    methods: methods.slice(0, limit).map(disp),
  });
}));

server.registerTool("accessors_of_field", {
  description: "Find methods reading (getters) and writing (putters) the given " +
    'field descriptor ("La/b/C;->name:Type").',
  inputSchema: {
    field_desc: z.string().describe("full field descriptor"),
    limit: z.number().int().min(1).max(1000).default(200),
  },
}, wrap(async ({ field_desc, limit = 200 }) => {
  const dk = requireDk();
  const getters = vecToArray(dk.findFieldGetMethods(field_desc));
  const putters = vecToArray(dk.findFieldPutMethods(field_desc));
  return jsonResult({
    getters: getters.slice(0, limit).map(disp),
    putters: putters.slice(0, limit).map(disp),
    truncated: getters.length > limit || putters.length > limit,
  });
}));

server.registerTool("references_to_type", {
  description: "Find structural references to a class type: fields of that type, " +
    "methods returning it, methods taking it as a parameter.",
  inputSchema: {
    class_desc: z.string().describe("class descriptor or dotted FQN"),
    limit_per_bucket: z.number().int().min(1).max(500).default(100),
  },
}, wrap(async ({ class_desc, limit_per_bucket = 100 }) => {
  const dk = requireDk();
  const cls = resolveClassDesc(class_desc);
  const r = dk.findTypeReferences(cls);
  const cap = (a) => a.slice(0, limit_per_bucket).map(disp);
  return jsonResult({
    class: cls,
    fields: cap(r.fields),
    methodsReturning: cap(r.methodsReturning),
    methodsWithParam: cap(r.methodsWithParam),
    truncated: r.fields.length > limit_per_bucket ||
      r.methodsReturning.length > limit_per_bucket ||
      r.methodsWithParam.length > limit_per_bucket,
  });
}));

server.registerTool("iocs", {
  description: "Extract indicators of compromise from string literals: network " +
    "indicators (URLs/IPs/domains by category) and sensitive content-provider " +
    "URIs, each with the classes referencing them." + DEX_ONLY,
  inputSchema: {},
}, wrap(async () => {
  const dk = requireDk();
  const r = dk.extractIocs();
  const mapClasses = (e) => ({ ...e, classes: e.classes.map(disp) });
  return jsonResult({
    network: r.network.map(mapClasses),
    providers: r.providers.map(mapClasses),
  });
}));

server.registerTool("capabilities", {
  description: "Behavioural capability profile: the engine matches bytecode " +
    "against its API catalog (categories like REFLECTION/DYNAMIC/STORAGE/SMS…, " +
    "permissions, flags) and resolves call sites. apiHits sorted by callSiteCount " +
    "descending." + DEX_ONLY,
  inputSchema: {
    app_only: z.boolean().default(true).describe("drop library/framework callers"),
    min_call_sites: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(1000).default(300),
  },
}, wrap(async ({ app_only = true, min_call_sites = 0, limit = 300 }) => {
  const dk = requireDk();
  const r = computeCaps(dk, app_only);
  const hits = r.apiHits
    .filter(h => h.callSiteCount + h.fieldAccessCount >= min_call_sites)
    .sort((a, b) => b.callSiteCount - a.callSiteCount);
  return jsonResult({
    ...r,
    apiHits: hits.slice(0, limit).map(h => ({ ...h, callers: h.callers.map(disp) })),
    apiHitsShown: Math.min(hits.length, limit),
    truncated: hits.length > limit,
  });
}));

server.registerTool("permissions", {
  description: "Permission→API→caller join over the engine's bundled permission " +
    "catalog. These are permissions IMPLIED by called APIs in the code — the " +
    "manifest's declared list is not available. Buckets: " +
    "dangerous/signature/internal/normal/other. Callers capped at 20 per API.",
  inputSchema: {
    app_only: z.boolean().default(true),
    bucket: z.enum(["dangerous", "signature", "internal", "normal", "other"]).optional(),
  },
}, wrap(async ({ app_only = true, bucket }) => {
  const dk = requireDk();
  const { permIndex, totals } = computePerms(dk, app_only);
  const rows = (bucket ? permIndex.filter(r => r.level === bucket) : permIndex)
    .map(r => ({
      perm: r.perm, level: r.level, api: r.api,
      callerCount: r.callers.length,
      callers: r.callers.slice(0, 20).map(disp),
    }));
  return jsonResult({ totals, bucket: bucket || "all", rows });
}));

server.registerTool("components", {
  description: "Android component CANDIDATES by superclass-chain walk (BFS to " +
    "transitive closure): activities, services, receivers, providers, plus " +
    "high-signal kinds (device-admin, accessibility, notif-listener, vpn, job, " +
    "application). NOT manifest-declared components — the manifest is not " +
    "available; runtime-registered and dead classes appear too." + DEX_ONLY,
  inputSchema: {},
}, wrap(async () => {
  const dk = requireDk();
  const groups = computeComponents(dk).map(g => ({
    kind: g.kind, tag: g.tag, count: g.classes.length,
    classes: g.classes.map(c => {
      const d = displayClassDesc(c);
      return d !== c ? { desc: c, display: d } : c;
    }),
  }));
  return jsonResult({ kinds: groups.length, groups });
}));

// ── boot ─────────────────────────────────────────────────────────────────────
await ensureEngine();
await server.connect(new StdioServerTransport());
process.stderr.write("dexllm MCP server ready (stdio)\n");
