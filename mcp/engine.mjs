// wasm engine boot + per-process session state for the dexllm MCP server.
// Mirrors ../worker.js's source bookkeeping (handleAddDump / rebuildDk,
// worker.js:122-172) — dumps shadow the original like the ART mirror does.
import fs from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

let Module = null;

export async function ensureEngine() {
  if (Module) return Module;
  const require = createRequire(import.meta.url);
  const createDexllm = require(join(repoRoot, "dexllm.js"));
  Module = await createDexllm({
    // Anything emscripten prints to stdout would corrupt JSON-RPC framing on
    // the stdio transport — route everything to stderr / nowhere.
    print: () => {},
    printErr: (s) => process.stderr.write(String(s) + "\n"),
    locateFile: (f) => join(repoRoot, f),
  });
  return Module;
}

// Every embind vector read goes through here so .delete() is never missed.
export function vecToArray(v, map) {
  try {
    const out = [];
    const n = v.size();
    for (let i = 0; i < n; i++) out.push(map ? map(v.get(i)) : v.get(i));
    return out;
  } finally {
    v.delete();
  }
}

// worker.js:66-98 — always return a STRING; translate emscripten CppException
// pointers so callers never see {"excPtr":N}.
export function describeError(err) {
  if (err == null) return "unknown error";
  if (typeof err === "string") return err;
  const ptr = (err && typeof err.excPtr === "number") ? err.excPtr : null;
  if (ptr != null) {
    if (Module && typeof Module.getExceptionMessage === "function") {
      try {
        const r = Module.getExceptionMessage(ptr);
        if (Array.isArray(r)) {
          const msg = r.filter(Boolean).map(String).join(": ");
          if (msg) return msg;
        }
        if (typeof r === "string" && r) return r;
      } catch (_) {}
    }
    return "wasm exception (excPtr=" + ptr + ")";
  }
  if (err.message) return String(err.message);
  if (err.name) return String(err.name);
  try {
    const s = JSON.stringify(err);
    if (s && s !== "{}") return s;
  } catch (_) {}
  return Object.prototype.toString.call(err);
}

// ── session: one APK per process ─────────────────────────────────────────────
export const session = {
  dk: null,                 // aggregated (or single-source) WasmDexKit
  originalSource: null,     // { vfs, label, slotCount, dk, dump:false }
  dumpedSources: [],        // [{ vfs, label, slotCount, dk, dump:true }]
  classes: null,            // cached dk.listClasses() as a plain array
  strings: null,            // lazy dk.listValueStrings() cache (search_symbols)
  decompiled: null,         // { cls, text } — last decompile, window moves are free
};

export function requireDk() {
  if (!session.dk) throw new Error("no APK loaded — call load_apk first");
  return session.dk;
}

function invalidateCaches() {
  session.classes = null;
  session.strings = null;
  session.decompiled = null;
}

export function classList() {
  if (!session.classes) session.classes = vecToArray(session.dk.listClasses());
  return session.classes;
}

export function stringList() {
  if (!session.strings) session.strings = vecToArray(session.dk.listValueStrings());
  return session.strings;
}

function resetState() {
  for (const s of session.dumpedSources) { try { s.dk.delete(); } catch (_) {} }
  if (session.dk && session.dk !== session.originalSource?.dk) {
    try { session.dk.delete(); } catch (_) {}
  }
  if (session.originalSource) { try { session.originalSource.dk.delete(); } catch (_) {} }
  session.dk = null;
  session.originalSource = null;
  session.dumpedSources = [];
  invalidateCaches();
}

// worker.js:122-139 — aggregate rebuild, dumps FIRST then original (lenient).
function rebuildDk() {
  const aliasesOrig = session.dk === session.originalSource?.dk;
  if (session.dk && !aliasesOrig) { try { session.dk.delete(); } catch (_) {} }
  session.dk = null;
  if (!session.dumpedSources.length) { session.dk = session.originalSource.dk; return; }
  const VS = new Module.VectorString();
  for (const d of session.dumpedSources) VS.push_back(d.vfs);
  VS.push_back(session.originalSource.vfs);
  try { session.dk = new Module.WasmDexKit(VS, true); }
  finally { VS.delete(); }
}

function writeVfs(vfs, bytes) {
  try { Module.FS.writeFile(vfs, bytes); } catch (_) {
    try { Module.FS.unlink(vfs); } catch (_) {}
    Module.FS.writeFile(vfs, bytes);
  }
}

export async function loadApk(path) {
  await ensureEngine();
  const bytes = fs.readFileSync(path);
  resetState();
  writeVfs("/input.bin", bytes);
  const dk = new Module.WasmDexKit("/input.bin");
  const slotCount = dk.verifyReport().length;
  session.originalSource = { vfs: "/input.bin", label: path, slotCount, dk, dump: false };
  session.dk = dk;
  return { dexCount: dk.dexCount(), classCount: classList().length, slotCount };
}

export async function addDump(path, label) {
  await ensureEngine();
  requireDk();
  const bytes = fs.readFileSync(path);
  const vfs = "/dump" + (session.dumpedSources.length + 1) + ".bin";
  writeVfs(vfs, bytes);
  const dk = new Module.WasmDexKit(vfs);
  const slotCount = dk.verifyReport().length;
  session.dumpedSources.push({ vfs, label: label || path, slotCount, dk, dump: true });
  rebuildDk();
  invalidateCaches();
  return { dexCount: session.dk.dexCount(), classCount: classList().length, sources: session.dumpedSources.length + 1 };
}
