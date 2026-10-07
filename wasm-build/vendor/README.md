# vendor/ — the in-browser IoC / provider / capability engine

Vendored from dexllm `c3ec1a1`. dexllm `4b085d8` ("refactor: remove web-only C++
IoC/capability/provider engine ports") deleted these from its core: dexllm's own
API uses the canonical pure-Python `dexllm.ioc` / `providers` / `capability`, so
the C++ mirrors existed only to back this WASM build. The dependency is one-way
(web → dexllm), so hosting web-serving C++ in dexllm's core inverted it. That
commit directs WASM consumers to vendor their own engine — this is that copy.

| File | Origin at `c3ec1a1` |
| --- | --- |
| `ioc.cpp` | `native/core_ext/ioc.cpp` |
| `public_suffix.cpp` | `native/core_ext/public_suffix.cpp` |
| `include/public_suffix.h` | `native/core_ext/include/public_suffix.h` |
| `include/web_analysis.h` | the IoC/provider/capability half of `native/core_ext/include/analysis.h` |
| `web_analysis.cpp` | `SummarizeCapabilities` from `native/core_ext/analysis.cpp` |
| `gen/psl_data.h` | `native/core_ext/gen/psl_data.h` |
| `gen/android_api_data.h` | `native/core_ext/gen/android_api_data.h` |
| `gen/content_uris_data.h` | `native/core_ext/gen/content_uris_data.h` |
| `gen/word_ranges.h` | `native/core_ext/gen/word_ranges.h` |

Bodies are byte-faithful to `c3ec1a1`. The only edits:

- `ioc.cpp` includes `web_analysis.h` instead of `analysis.h` (the declarations
  moved when dexllm's `analysis.h` lost them; it now declares only
  `PermissionCallers`, which stayed in the core and is still consumed directly).
- `web_analysis.h` includes dexllm's `analysis.h` rather than redeclaring
  `DexKitExt`.

Everything stays in `namespace dexkit::ext`, so call sites in `wasm_module.cpp`
are unchanged.

## Parity caveat

Upstream's guarantee was that this C++ is byte-identical to the Python path,
enforced by differential tests (`tests/test_ioc_native.py`,
`tests/test_capability_native.py`) and a full-corpus gate. Those tests were
deleted alongside the sources, so **nothing re-verifies that parity now**. The
codegen scripts (`scripts/gen_psl_data.py` and siblings) were also removed, so
the bundled PSL and API catalog are frozen at `c3ec1a1` and will drift from
upstream AOSP/PSL data until regenerated. Recover either from dexllm history
(`git show c3ec1a1:<path>`) if that becomes worth maintaining.
