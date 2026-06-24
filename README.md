# dexllm-web

In-browser DEX / APK decompiler. WebAssembly build of
[dex-analyzer-for-llm](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm)
— drop a `.apk` / `.dex` / `.jar` onto the page and it decompiles entirely on
your device, no upload.

## Run it

- **Hosted demo**: <https://mobile-threat-hunter.github.io/dexllm-web>
- **Windows local**: download
  [`dist/dexllm-web.exe`](dist/dexllm-web.exe), double-click — a console window
  prints the local URL and the default browser opens. The entire UI runs from
  `127.0.0.1` with no further network traffic. Source + build instructions in
  [`cmd/dexllm-web/`](cmd/dexllm-web/).

## Why an .exe instead of just opening index.html

The engine uses a Web Worker plus a streaming-compiled wasm module, both of
which require a real HTTP origin — browsers refuse them under `file://`. The
launcher is a ~7 MB Go binary that binds 127.0.0.1 on a random port, opens
the default browser, and serves the embedded bundle. No installer, no
dependencies, no system-wide changes.
