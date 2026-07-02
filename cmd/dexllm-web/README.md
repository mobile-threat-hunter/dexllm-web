# dexllm-web — local launcher (Windows)

Bundles the dexllm-web demo into a single ~7.4 MB Windows executable. The
hosted GitHub Pages version (https://mobile-threat-hunter.github.io/dexllm-web)
needs an internet connection on every load; this build runs the same UI from
the user's own machine — no network calls after the .exe is downloaded.

## Use

1. Grab `dexllm-web.exe` from `dist/` (or the latest release).
2. Double-click it. A console window opens with the URL it's serving on
   (a random loopback port like `http://127.0.0.1:41075/`).
3. The default browser opens automatically with the page loaded. If it
   doesn't, copy the URL out of the console window.
4. Drop an `.apk` / `.dex` / `.jar` onto the page — decompilation runs
   entirely locally (WASM, no upload).
5. Close the console window or press Ctrl+C to stop the server.

## Why an HTTP server (not just open the .html)

The engine uses a Web Worker plus a wasm fetched through emscripten's
`locateFile` callback. Browsers refuse both under the `file://` protocol:

- Workers must come from a same-origin HTTP(S) URL
- `WebAssembly.instantiateStreaming` rejects non-http origins

A tiny in-process server is the smallest way to satisfy both without
asking the user to install Node / Python / nginx.

## Build from source

```
cd cmd/dexllm-web
go build -ldflags="-s -w" -trimpath -o dexllm-web    # native
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-s -w" -trimpath \
  -o ../../dist/dexllm-web.exe                       # Windows cross-build
```

The `static/` directory next to `main.go` holds the embedded assets — copies of
`index.html`, `worker.js`, `dexllm.js`, `dexllm.wasm`, `perm_api.json`,
`perm_levels.json`, `loop.mp4`, `trans.mp4` from the repo root. After updating those at the repo
root (a `chore: refresh wasm` cycle, say), refresh the copies and rebuild.

## Security posture

- Binds **127.0.0.1 only** — no LAN exposure of whoever's analyzing a sample.
- Random free port — no collision with whatever else is bound to a fixed port.
- Aggressive `Cache-Control: no-store` so a fresh launch with an updated
  bundle never serves the old cached version through the user's browser.
- `Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy:
  require-corp` set in case a future build wants `SharedArrayBuffer` for a
  multi-threaded WASM rebuild.
