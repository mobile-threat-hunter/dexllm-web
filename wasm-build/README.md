# wasm-build — the emscripten/embind project behind `dexllm.js` / `dexllm.wasm`

The engine shipped at the repo root (`dexllm.js` + `dexllm.wasm`) is **not**
built by the dexllm core repo — that only builds the pybind11 Python module.
It is produced here: a small emscripten/[embind](https://emscripten.org/docs/porting/connecting_cpp_and_javascript/embind.html)
wrapper that exposes the DexKit + DAD C++ engine to JavaScript as
`createDexllm()` → `Module.WasmDexKit`.

This directory was previously kept in ephemeral `/tmp` and lost on reboot;
it now lives in-repo so a sync is reproducible.

## Files

| File | Role |
|---|---|
| `wasm_module.cpp` | The embind bindings — defines `WasmDexKit` and every method `index.html` / `worker.js` call. |
| `CMakeLists.txt` | The build. Compiles the vendored DexKit Core + dexllm's `native/` sources + this binding into one wasm module. |
| `smoke.mjs` | Node smoke test — loads bare `.dex` / `.apk` forms and exercises the API the web app uses. |

The dexllm **core sources are not vendored here** — the build pulls them from a
separate dexllm checkout via `-DDEXLLM_ROOT` (default expectation:
`$HOME/Project/dexllm`).

## Build

```sh
source ~/emsdk/emsdk_env.sh            # emcc 6.0.0 was used for the current build
cd wasm-build
emcmake cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DDEXLLM_ROOT=/abs/path/to/dexllm
ninja -C build dexllm                  # → build/dexllm.js + build/dexllm.wasm
node smoke.mjs                         # optional: verify against the local test APKs
```

`build/`, and any `dexllm.js` / `dexllm.wasm` copied here, are gitignored.

## Syncing a new engine into the site

1. Check out the target commit in the dexllm core repo.
2. Rebuild here (above).
3. Copy `build/dexllm.js` + `build/dexllm.wasm` to the repo root.
4. Bump the build SHA in **three** places in `index.html`:
   `window.__DEXLLM_BUILD`, the `dexllm.js?v=` `<script src>`, and the header
   commit link — plus the SHA in `docs/dexllm-integration.md`.
5. `bash cmd/dexllm-web/build.sh` to refresh `dist/dexllm-web.exe`.
6. Verify (node smoke + a browser drop-test) and commit as
   `sync: dexllm <old> → <new>`.

## Build notes

- **Single-threaded** on purpose (`-pthread` OFF): the vendored DexKit ThreadPool
  has an Emscripten shim that runs tasks inline, and GitHub Pages can't send the
  COOP/COEP headers `SharedArrayBuffer` would need.
- **`-fexceptions` everywhere**: the slicer / dexllm guards throw
  `std::runtime_error` / `std::exception`; without exceptions those catches
  silently miss and a stray `stoi` throw becomes an unrecoverable wasm trap.
- **`STACK_SIZE=16MB`** (up from 4MB): some classes (e.g. `La2dp/Vol/ALauncher;`)
  recurse deep during decompile.
- Link flags of note: `MODULARIZE=1`, `EXPORT_NAME=createDexllm`,
  `EXPORTED_RUNTIME_METHODS=['FS','getExceptionMessage']`, `FORCE_FILESYSTEM=1`,
  `ALLOW_MEMORY_GROWTH=1`, `USE_ZLIB=1`.
- emscripten 6 dead-code-eliminates hard — the current wasm is ~1.4 MB, down
  from ~2.1 MB on older toolchains, with the same binding surface.
