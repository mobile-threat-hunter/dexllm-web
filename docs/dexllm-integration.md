# dexllm-web — how the web app is built on the dexllm engine

This document explains how **dexllm-web** wraps the
[dex-analyzer-for-llm](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm)
("dexllm") engine and drives its API to build a fully client-side DEX / APK
decompiler that runs in the browser — no server, no upload.

- **Hosted demo:** <https://mobile-threat-hunter.github.io/dexllm-web>
- Companion docs: [`xref.md`](xref.md) (cross-reference subsystem),
  [`d3-pc-line-map.md`](d3-pc-line-map.md) (smali ↔ Java PC line mapping).

---

## 1. What "dexllm" is here

dexllm is a native C++ DEX analysis / decompilation engine. In this repo it is
**not** an HTTP API and **not** a hosted service — it is compiled to
**WebAssembly** with Emscripten and shipped as two static artifacts that the
page loads directly:

| Artifact | Size | Role |
|---|---|---|
| [`dexllm.wasm`](../dexllm.wasm) | ~2.1 MB | The compiled engine (all DEX parsing + decompilation logic). |
| [`dexllm.js`](../dexllm.js) | ~110 KB | Emscripten glue: `MODULARIZE` factory `createDexllm`, the embind class bindings, and the virtual filesystem (`Module.FS`). |

Because the engine runs as WASM inside the user's browser, **the analyzed file
never leaves the device.** That is the core privacy property of the product.

The engine is exposed to JavaScript through Emscripten **embind** as a single
C++ class, `Module.WasmDexKit`, plus a few helper types (`Module.VectorString`,
`Module.FS`, `Module.getExceptionMessage`).

---

## 2. Loading the engine

The page pins a build tag and cache-busts every engine asset with `?v=<tag>`
so a redeploy never serves a stale wasm against a fresh glue file
([`index.html:851`](../index.html#L851)):

```html
<script>window.__DEXLLM_BUILD = "3ca7d90-2";</script>
<script src="dexllm.js?v=3ca7d90-2"></script>
```

The tag is `<dexllm commit>-<rebuild counter>`. The counter exists because
`wasm-build/wasm_module.cpp` can change without the engine moving, and the
browser still has to refetch — bump on every wasm rebuild, not every sync.

The main thread instantiates the module with a `locateFile` hook so the wasm
is fetched with the same cache-buster ([`index.html:1325`](../index.html#L1325)):

```js
createDexllm({ locateFile: (f) => f + "?v=" + window.__DEXLLM_BUILD }).then(m => {
  Module = m;
  statusEl.innerHTML = "engine ready · <b>drop a file</b>";
});
```

### Why it needs a real HTTP origin

Both the Web Worker and `WebAssembly.instantiateStreaming` are rejected by
browsers under `file://`. That is why simply opening `index.html` from disk
does **not** work, and why the repo ships a tiny Go launcher
([`cmd/dexllm-web/main.go`](../cmd/dexllm-web/main.go)) that binds
`127.0.0.1` on a random port and serves the embedded bundle for offline /
Windows use. On the web, GitHub Pages provides the HTTP origin.

---

## 3. Two-thread architecture (main thread + worker)

Decompilation in wasm is **synchronous** on the calling thread — a heavy class
can block for many seconds. To keep the UI responsive, the app runs the engine
in **two places at once**:

```
┌─────────────────────────── main thread (index.html) ───────────────────────────┐
│ createDexllm() → Module.WasmDexKit                                               │
│   • fast, structural queries (class lists, xref, strings, smali, perms)          │
│   • everything that must feel instant                                            │
└─────────────────────────────────────────────────────────────────────────────────┘
                    │  new Worker("worker.js")   ▲  postMessage {id, ok, result}
                    ▼  postMessage {id, type…}   │
┌─────────────────────────────── worker.js ───────────────────────────────────────┐
│ importScripts("dexllm.js") → its OWN parallel set of WasmDexKits                  │
│   • decompileClassJava()  ← the slow work, off the UI thread                      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

Two independent WASM instances are loaded (one per thread); they do **not**
share memory. The main thread keeps its `WasmDexKit`(s) for interactive
queries; the worker keeps a mirrored set purely for decompilation.

### The worker protocol

Defined in [`worker.js`](../worker.js). Every message carries an opaque `id`
that the worker echoes so the main thread can pair the reply to a pending
Promise:

```
main → worker: { id, type: "init",     buildSha }
               { id, type: "load",      bytes, label }
               { id, type: "addDump",   bytes, label, vfs }
               { id, type: "addIsolated", bytes, vfs, key }
               { id, type: "decompile", cls, sourceIdx, isolatedKey }
               { id, type: "reset" }
worker → main: { id, ok: true,  result }
               { id, ok: false, error }
```

The main-thread side is a thin promise wrapper
([`index.html:1365`](../index.html#L1365)):

```js
const worker = new Worker("worker.js?v=" + window.__DEXLLM_BUILD);
function wcall(msg, transfer) {
  const id = _wid++;
  return new Promise((res, rej) => {
    _pending.set(id, { resolve: res, reject: rej });
    worker.postMessage({ ...msg, id }, transfer || []);
  });
}
wcall({ type: "init", buildSha: window.__DEXLLM_BUILD });
```

The worker **serializes all messages through a single in-order queue**
([`worker.js:208`](../worker.js#L208)) so a `decompile` posted immediately
after `load` is guaranteed to see the VFS file already written — handlers can't
race.

---

## 4. Data flow: from dropped file to rendered code

1. **Intake.** User drops an `.apk` / `.dex` / `.jar`. The main thread reads
   the bytes and writes them into the WASM virtual filesystem, then constructs a
   DexKit over that path:

   ```js
   Module.FS.writeFile("/input.bin", bytes);
   const dk = new Module.WasmDexKit("/input.bin");
   ```

   The identical bytes are also handed to the worker via `wcall({type:"load", …})`
   so both instances hold the same source ([`worker.js:140`](../worker.js#L140)).

2. **Structural analysis (main thread, instant).** The app calls DexKit query
   methods to populate the class list, string tables, IoC panel, and
   dangerous-permission panel — see the API map in §5.

3. **Decompile on demand (worker, async).** Clicking a class sends
   `wcall({type:"decompile", cls, sourceIdx})`; the worker runs
   `dk.decompileClassJava(cls)` off the UI thread and posts the Java text back
   ([`worker.js:170`](../worker.js#L170)).

4. **Render + tokenize.** The main thread syntax-highlights the returned Java
   into clickable `.tk-*` tokens, which the xref subsystem hangs navigation on
   (see [`xref.md`](xref.md)).

### Multiple sources: Runtime vs Isolated

The app supports adding runtime-dumped dexes on top of the original APK. Both
threads keep a **parallel, order-matched set of DexKits** so cross-source
routing stays consistent:

- **Runtime mode** (`addDumpedDex` → `addDump`): dumped dexes are aggregated
  into one `WasmDexKit(VectorString, true)`. Sources are ordered **dumps first,
  original last**, so on a class collision the unpacked/dumped class wins
  (first-wins) — mirroring ART after a packer unpacks
  ([`worker.js:121` `rebuildDk()`](../worker.js#L121)).
- **Isolated mode** (`addIsolatedDex` → `addIsolated`): each `classes*.dex`
  gets its **own** single-dex `WasmDexKit`, keyed by global dex id, so per-dex
  IoC / permission panels are truly isolated with no first-wins aggregation
  ([`worker.js:187`](../worker.js#L187)).

---

## 5. The dexllm API surface used

Everything the web app can do is a call into `Module.WasmDexKit`. The methods
actually invoked across [`index.html`](../index.html) and
[`worker.js`](../worker.js), grouped by the feature they power:

### Loading & structure
| Method | Used for |
|---|---|
| `new WasmDexKit(path)` / `new WasmDexKit(VectorString, true)` | Construct a single-source or aggregated multi-source kit. **Both load leniently** — see below. |
| `verifyReport()` | Slot/dex count + integrity per source. |

**Every load in the web app is lenient** (`DexKitExt(..., lenient=true)`:
ART-structural-equivalent verification with `VerifyInsns` off). The multi-source
ctor is passed `true` explicitly; the single-path ctor defaults to it in
`wasm-build/wasm_module.cpp`. The reason is the input mix — this tool is aimed at
packed and obfuscated samples, and strict instruction verification throws away a
whole dex over bytecode a real device would run, which leaves the analyst with
nothing. Measured on 300 corrupted-but-structurally-valid dexes, lenient loaded
32 that strict rejected and lost none. The cost is that the decompiler now walks
unverified instruction streams, which the reader paths are already written for
(the bounds guards in `dex_item.cpp` / `dataflow.cpp`); a malformed body fails
that one method instead of the load. The `verified ✓` status pill therefore means
the structural bar, and its tooltip says so.
| `dexCount()` | Number of dexes in the kit. |
| `extractDexBytes(dexId)` | Pull one dex's raw bytes out (feeds Isolated-mode per-dex kits). |
| `listClasses()` / `listClassesInDex()` | Populate the sidebar class list. |
| `listClassMethods()` / `listClassFieldDescriptors()` | Class member listings. |
| `locateClassDex(cls)` | Which dex a class lives in (also "is this external?"). |
| `getClassSuperAndInterfaces()` | Type-hierarchy popup. |

### Decompilation & smali (the "↔ smali" toggle, type inference)
| Method | Used for |
|---|---|
| `decompileClassJava(cls)` | **Primary output** — full Java for a class (runs in the worker). |
| `renderMethodSmali(methodDesc)` | The smali pane; backs the **↔ smali** toggle and the smali↔Java line sync. |
| `decompileMethodJavaWithPc(...)` | Java with per-line PC info, used to map smali lines ↔ Java lines. |

### Cross-references (the xref subsystem)
| Method | Used for |
|---|---|
| `findCallSitesToApi(desc)` / `findCallSitesWithOffset(...)` | Caller popups for a method / API. |
| `findCallSitesFromMethod(desc)` | The FORWARD direction — every invoke inside a method as `{callee, offset, opcode}`. Joined to `decompileMethodJavaWithPc`'s pcMap to break callee ties the receiver text can't. |
| `findMethodsByName` / `findMethodsUsingString` | Method search & string→method links. |
| `findFieldGetMethods` / `findFieldPutMethods` | Field **READ BY / WRITTEN BY** popups. |
| `findClassesByName` / `findClassesBySuperclass` / `findClassesImplementing` | Class search & hierarchy navigation. |
| `findTypeReferences` / `listExternalTypeRefs` / `listExternalMethodRefs` | Type/ref cross-navigation. |
| `listAllMethodDescriptors` / `listAllFieldDescriptors` | Global indexes the xref resolver builds on. |

### Strings & indicators
| Method | Used for |
|---|---|
| `listValueStrings()` | The Strings tab. |
| `xrefStringsToClasses()` / `findClassesWithStaticValueString()` | String → owning class links. |

### Lifecycle
| Method | Used for |
|---|---|
| `delete()` | Free a kit's WASM memory on reset / rebuild (manual — embind objects aren't GC'd). |

Supporting Emscripten APIs: `Module.FS` (write dropped bytes into the VFS,
22 call sites), `Module.VectorString` (pass multi-source path lists),
`Module.getExceptionMessage` (translate C++ exception pointers into readable
strings).

---

## 6. Feature → engine mapping

The user-facing features and the dexllm calls behind each:

| Feature (UI) | Backed by |
|---|---|
| Class browser sidebar | `listClasses`, `listClassesInDex`, `locateClassDex` |
| Java decompilation view | `decompileClassJava` (worker) |
| **↔ smali** toggle & line-sync | `renderMethodSmali`, `decompileMethodJavaWithPc` |
| Click-to-navigate xref (callers, callees, field get/set, type hierarchy) | the `find*` / `xref*` family in §5 (see [`xref.md`](xref.md)) |
| **Indicators** panel (network IOCs + content providers) | `WasmDexKit.extractIocs()` — one engine call returns `{network:[{value,category,classes[]}], providers:[{uri,family,classes[]}]}`, with the public-suffix list + content-URI dataset **bundled in the engine**. Each row navigates to the caller. |
| **Capabilities** tab (same panel as permissions) | `WasmDexKit.summarizeCapabilities()` — one call returns the behavioural profile over the engine's **bundled** API catalog: `{categories, permissions, apiHits:[{apiSignature, permissions[], categories[], callSiteCount, callers[]}], byCaller, catalogVersion, catalogSize, matchedApis, totalCallSites}`. Covers un-gated behaviour (REFLECTION, DYNAMIC, STORAGE…) that the permissions view structurally cannot show. |
| **Permissions** panel (all protection levels) | `WasmDexKit.permissionCallers(appOnly)` — the engine does the whole permission→API→callers join over its **bundled** perm→API table + protection levels, returning `[{perm, protectionLevel, rows:[{api, descriptors[], callers[]}]}]`. The panel groups/filters by dangerous / signature / normal / internal. |
| **Components** tab + sidebar class badges | `WasmDexKit.findClassesBySuperclass()`, BFS'd to the transitive closure of ten Android component bases (activity / service / receiver / provider / application, plus device-admin, accessibility, notification-listener, VPN, job). Reported as **candidates**: the engine only sees dex bytes, so `AndroidManifest.xml` cannot confirm a class is actually declared — and a class registered at runtime or never declared still shows up, which is usually the interesting case. |
| Strings tab | `listValueStrings`, `xrefStringsToClasses` |
| Runtime / Isolated dex modes | multi-source `WasmDexKit` aggregation vs per-dex isolation |

---

## 7. Error handling across the WASM boundary

Emscripten throws C++ exceptions as `{ excPtr: number }` objects. Naively
stringifying one leaks a raw pointer to the user (e.g.
`decompile failed: {"excPtr":35302424}`). Both threads share a `describeError`
helper ([`index.html:1337`](../index.html#L1337),
[`worker.js:65`](../worker.js#L65)) that routes such objects through
`Module.getExceptionMessage(ptr)` and always returns a plain human-readable
string — the inner call is itself guarded because it can throw "memory access
out of bounds" if the exception was already freed.

---

## 8. File map

| Path | Role |
|---|---|
| [`index.html`](../index.html) | The entire app: UI, main-thread engine instance, xref, panels, rendering (~4.6k lines). |
| [`worker.js`](../worker.js) | Background decompile worker + multi-source DexKit mirror. |
| [`dexllm.js`](../dexllm.js) / [`dexllm.wasm`](../dexllm.wasm) | The Emscripten-compiled dexllm engine + glue. The AOSP datasets (perm→API table, protection levels, public-suffix list, `content://` URIs) are **bundled inside the wasm** and exposed via `permissionCallers()` / `extractIocs()` / `summarizeCapabilities()` — the web app no longer ships or joins them (dex-analyzer-for-llm#13). |
| [`wasm-build/`](../wasm-build/) | The embind project (`wasm_module.cpp` + `CMakeLists.txt`) that builds `dexllm.js`/`.wasm` against a dexllm checkout. [`wasm-build/vendor/`](../wasm-build/vendor/) holds the IoC / content-provider / capability engine, which dexllm dropped from its core in `4b085d8` as web-only — see its README. `permissionCallers()` still comes from dexllm itself. |
| [`cmd/dexllm-web/`](../cmd/dexllm-web/) | Go launcher that serves the bundle over `127.0.0.1` for offline / Windows use. |
| [`dist/dexllm-web.exe`](../dist/) | Prebuilt Windows launcher. |
| [`docs/`](.) | This doc plus `xref.md` and `d3-pc-line-map.md`. |
</content>
</invoke>
