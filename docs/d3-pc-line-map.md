# D-3: Precise smali ↔ Java line sync — dexllm upstream proposal

**Status:** spec / design — not yet implemented.
**Target repo:** `mobile-threat-hunter/dex-analyzer-for-llm` (the dexllm core).
**Consumer:** dexllm-web (this repo), bucket D-3 in [`docs/xref.md`](xref.md).

The xref subsystem currently has 8 of 16 JEB/jadx-parity gaps implementable
with existing dexkit primitives (bucket A — landed). Bucket D's only entry is
**smali ↔ Java line sync**: the user clicks a Java line, the smali pane
scrolls to the corresponding bytecode; clicking a smali instruction goes the
other way. This needs a `(java_line, bytecode_offset)` map that doesn't
currently cross the DAD ↔ smali boundary.

Two cheaper variants (D-1 side-panel, D-2 heuristic anchor matching) cover
~80–90% of cases without upstream changes. **D-3 is for the remaining 10–20%
where heuristic order-matching breaks** — primarily:
- Lines with multiple anchors (`a().b().c()` — 3 invokes, can't tell which
  invoke the cursor token belongs to)
- Short-circuit conditions packed on one line (`(x && y) || z` — 3 if-test
  branches in one source line)
- Methods rewritten by DAD's `RegisterPropagation` / `Simplify` such that
  one Java statement collapses several dex ops, or vice versa

D-3 also gives us the precise bytecode offset to display alongside each Java
line — useful for anti-tamper / unpacker work where dex offsets are the
ground truth identity.

## Why this is a dexllm change, not a dexllm-web one

The data already exists inside dexllm: `MethodSnapshot::ins_storage[].byte_off`
is the per-instruction PC. **The IR layer drops it** during construction.
DAD's `IRForm` (the base of every instruction-level IR node) has no field for
"which `RawIns` did I come from", and the Writer / JSONWriter doesn't carry
the mapping into the emitted text/AST. To recover it in dexllm-web, we'd
have to re-render and re-parse — the information is gone by the time it
reaches the wasm boundary.

The fix is to thread the offset through IR construction and emit it from the
Writer. **Zero impact on DAD parity** (the change is metadata-only; text/AST
output is byte-identical).

## Concrete proposal

### Step 1 — add `source_byte_off` to `IRForm`

File: `native/dad_cpp/include/instruction.h`

```cpp
class IRForm {
public:
    // ... existing virtuals ...

    // D-3 — bytecode offset of the dex instruction this IR node was built
    // from. UINT32_MAX = synthesized node (loop headers, short-circuit wraps,
    // structural braces — no underlying RawIns). Propagated by Writer /
    // JSONWriter into the emitted line map. Zero impact on DAD parity:
    // metadata only, never read by IR transforms.
    uint32_t source_byte_off = UINT32_MAX;
};
```

`uint32_t` matches `RawIns::byte_off`. `UINT32_MAX` is the sentinel
already used in `RawIns::branch_target` for "N/A" — consistent.

### Step 2 — set `source_byte_off` at IR construction time

Files: `native/dad_cpp/opcode_ins.cpp` (the 229 handlers), `instruction.cpp`,
`basic_blocks.cpp`.

Each `OpcodeHandler` already receives the `RawIns` (or its decoded form) it's
processing — that's where IR nodes are created. At each construction site:

```cpp
// Before (existing):
auto node = std::make_shared<NewInstance>(...);

// After:
auto node = std::make_shared<NewInstance>(...);
node->source_byte_off = ins.byte_off;
```

For nodes created inside structural transforms (e.g. `ShortCircuitStruct` in
`control_flow.cpp` synthesizes a wrap node from existing IR), the wrap
inherits the source offset of its first child — same intuition as
`Interval::ComputeEnd` picking the max-num content member.

For nodes that genuinely correspond to nothing in the dex (NopExpression
emitted for a removed dead block, structural braces), leave the default
`UINT32_MAX`.

**Mechanical scope:** ~200 sites across `opcode_ins.cpp`. Each is a 1-line
addition. Recommend a sed-style first pass + manual review.

### Step 3 — Writer records the map during emit

File: `native/dad_cpp/writer.cpp`

The Writer already maintains `out_` (the output buffer). Add a parallel
`pc_map_` and a `current_line()` helper:

```cpp
class Writer {
public:
    // ... existing state ...

    // D-3 — populated as side-effect of WriteMethod. Each entry maps a Java
    // source line (1-based) to the dex bytecode offset of the originating
    // instruction. Lines with no underlying RawIns (closing braces, blank
    // separators) get UINT32_MAX; the consumer renders those as "—".
    std::vector<std::pair<uint32_t /* line */, uint32_t /* byte_off */>>
        pc_map_;

private:
    uint32_t current_line_ = 1;

    void emit_newline() {
        out_ += '\n';
        ++current_line_;
    }

    // Stamp current_line_ → ir->source_byte_off into pc_map_. Called from
    // each visit_X just before the first emit for that node.
    void record_line(const IRForm* ir) {
        if (!ir || ir->source_byte_off == UINT32_MAX) return;
        if (!pc_map_.empty() && pc_map_.back().first == current_line_) return;
        pc_map_.emplace_back(current_line_, ir->source_byte_off);
    }
};
```

Every `visit_X(X* ir)` calls `record_line(ir)` at the start. The check
"don't push if same line already recorded" preserves the first-anchor-wins
semantics (matches user mental model: line N belongs to its FIRST observable
dex op).

### Step 4 — JSONWriter records the same map (AST variant)

File: `native/dad_cpp/dast.cpp`

Same pattern as Step 3 but written into the AST tree as a node-level `pc`
field (each statement-level AST node gets `pc: 0xNN | null`).

DAST output format extends from:
```json
{ "kind": "MethodInvocation", "target": ..., "args": [...] }
```
to:
```json
{ "kind": "MethodInvocation", "target": ..., "args": [...], "pc": 18 }
```

`pc` is integer or `null`. AST consumers that don't need the offset ignore
the field (forward-compatible).

### Step 5 — new public API on `Decompiler`

File: `native/dad_cpp/decompiler.cpp`, header in `decompiler.h`

Add a sibling to `DecompileMethod`:

```cpp
struct DecompiledMethodWithMap {
    std::string source;
    std::vector<std::pair<uint32_t, uint32_t>> pc_map;
    // pc_map[i] = (line_1based, byte_off). Sorted ascending by line.
};

DecompiledMethodWithMap DecompileMethodWithPcMap(std::string_view descriptor);
```

The existing `DecompileMethod` keeps its signature (text-only). Cache
strategy: store both flavors in the LRU? — probably overkill, just store
text + the map together and let `DecompileMethod()` return `.source`.

### Step 6 — pybind11 binding

File: `native/binding/module.cpp`

```python
dk.decompile_method_java_with_pc(desc: str) -> dict
# Returns: {"source": str, "pc_map": [[line, byte_off], ...]}
```

GIL released for the compute window (same as the existing
`decompile_method_java`).

### Step 7 — WASM binding (in dexllm-web's `wasm_module.cpp`)

```cpp
val decompileMethodJavaWithPc(const std::string& desc) const {
    val obj = val::object();
    auto r = decompiler_->DecompileMethodWithPcMap(desc);
    obj.set("source", r.source);
    val arr = val::array();
    std::size_t i = 0;
    for (const auto& [line, off] : r.pc_map) {
        val o = val::object();
        o.set("line", line);
        o.set("offset", static_cast<int>(off));
        arr.set(i++, o);
    }
    obj.set("pcMap", arr);
    return obj;
}
```

### Step 8 — dexllm-web consumer (the actual D-3 UI)

In `index.html`'s xref banner block (per the "keep grouped" rule):

```js
// ── Smali ↔ Java sync (D-3) ─────────────────────────────────────────────
function showSmaliPaneFor(methodDesc) {
  const useDk = activeQueryDk();
  const { source, pcMap } = useDk.decompileMethodJavaWithPc(methodDesc);
  const smali = useDk.renderMethodSmali(methodDesc);
  // Render two panes side-by-side; both keep their own scroll.
  // Click handler on Java pane: read line N, look up pcMap[N].offset,
  // scroll smali pane to the line whose `0xNN:` prefix matches.
  // Reverse direction: parse smali line's offset, find pcMap entry whose
  // .offset is closest <= the smali offset, scroll Java to that line.
}
```

UI shell: a docked right-side pane (640px), toggled by a button next to the
existing dex tabs. Same chrome as the existing decompile viewer (font, line
height) so the two panes line up visually.

## What about the AST path?

`decompile_method_ast` is the dast.py 1:1 port. With Step 4, every
statement-level AST node carries a `pc`. This means **any consumer of the
AST** (not just text + line-map) can drive the smali sync — e.g. an
expression-tree viewer that wants per-token offsets, an instruction-level
debugger UI, or external tools that consume DAD AST.

## Risks + how to retire them

### Risk 1: IR transforms drop the offset

`DeadCodeElimination`, `RegisterPropagation`, `Simplify` rewire nodes —
some create NEW nodes from old. **Mitigation:** when one node replaces
another (typical pattern: `n_map[old] = new`), the new node inherits
`source_byte_off`. Add an audit pass that asserts: every IR node reachable
from a block's `ins` list at Writer time has a non-`UINT32_MAX`
`source_byte_off`. Run that assertion in the parity test suite — if it ever
fires, we've found a pass that silently drops the offset.

### Risk 2: One Java line maps to several dex offsets

Common: `a + b * c` → 2 binary ops → 2 RawIns. The Writer's
"first-anchor-wins" rule picks the first one observed. Consumer impact:
clicking the line scrolls smali to the FIRST related instruction. That's
fine — the user can scroll forward to see the rest of that statement's ops.

If we want to be richer, replace `pair<line, byte_off>` with
`pair<line, vector<byte_off>>` and let the consumer pick. Defer until a
user complains; YAGNI.

### Risk 3: Some Java lines have no source op

`}` closing braces, blank separators between methods, structural artifacts
from `IfStruct`/`CatchStruct`. Those lines simply don't appear in
`pc_map_`. The consumer's lookup is `pcMap.find(line)` → null → no sync,
graceful no-op.

### Risk 4: AST schema is now a moving target

Adding a `pc` field is backwards-compatible: old consumers ignore it. But if
we ever change the schema again, downstream tools relying on the AST will
need to be checked. **Mitigation:** the AST is documented in
`docs/architecture.md` of dexllm — update there.

### Risk 5: Performance regression

The map is `vector<pair<uint32_t, uint32_t>>`. ~hundreds of entries per
method. Single allocation per `DecompileMethod` call — negligible.

`record_line()` runs per visit_X call, which is ~1× per IR node. Already
on a hot path; the per-call cost is a comparison + maybe a vector push.
Conservatively <1% wall-clock overhead.

Verify with `/dexkit-bench` before/after — must not regress >2%.

## Acceptance criteria

1. **DAD parity unchanged.** `tests/parity/` 28 suites all pass.
2. **Sweep clean.** `/dexkit-sweep` on the existing 22-APK corpus: 0 crashes,
   throughput within 2% of baseline.
3. **New test.** `tests/test_pc_line_map.py` — decompile a hand-picked
   method, assert (a) every Java line that mentions an invoke / iget / sget
   / new-instance / const-string has a `pc_map` entry, (b) the entry's
   `byte_off` matches the actual smali offset of that op.
4. **Audit pass.** Add `tests/test_pc_map_coverage.py` — for every method in
   a corpus subset, walk `pc_map` and verify the offsets correspond to real
   `RawIns` byte offsets in the snapshot.
5. **AST forward-compat.** Existing `decompile_method_ast` consumers (the
   dexllm-web AST display, if any) still parse cleanly with the new `pc`
   field present.

## Estimated effort

| Step | LoC | Risk |
|---|---|---|
| 1. `IRForm` field | 1 | trivial |
| 2. Plumb through opcode handlers | ~200 (~1 line × 200 sites) | mechanical |
| 3. Writer pc_map | ~30 | low — pure addition |
| 4. JSONWriter pc field | ~40 | low — pure addition |
| 5. `DecompileMethodWithPcMap` API | ~20 | low |
| 6. pybind11 binding | ~15 | low |
| 7. WASM binding (downstream) | ~15 | low |
| 8. dexllm-web smali pane UI | ~150 | medium — UI layout, scroll math |
| Tests | ~100 | — |
| **Total** | **~570** | one PR per repo |

One dexllm PR (Steps 1–6, ~410 LoC + 100 LoC tests), one dexllm-web PR
(Steps 7–8, ~165 LoC). Sequencing: dexllm first, then dexllm-web after the
new wasm artifact is in.

## Alternatives considered

### Alternative A: emit `// @ 0xNN` comments inline in the text

DAD's Writer emits Java text. We could append `// @ 0xNN` on each emitted
statement. **Rejected:** breaks byte-identical-to-androguard parity
(`docs/xref.md` invariant 1 — DAD-faithful) and forces every consumer to
strip the comments. The separate-map design is cleaner.

### Alternative B: snapshot-only map (no IR involvement)

Use the existing `MethodSnapshot.blocks[].ins[].byte_off` and try to map
Java text lines to smali by structural anchoring after the fact.
**Rejected:** that's just D-2 (the heuristic) dressed up. We'd lose the
precision exactly where we need it (transformed lines).

### Alternative C: source-line metadata in `MethodSnapshotBuilder`

Build the map at snapshot time, before IR construction.
**Rejected:** there's no Java text at snapshot time — Java lines don't exist
until the Writer runs. The map necessarily lives between IR construction and
text emission.

## Open questions for the dexllm maintainers

1. Is a parallel map (Step 5 — `DecompiledMethodWithPcMap`) preferred to a
   field on a generalized return struct?
2. AST-level `pc` field — is `null` acceptable, or should we use `0`
   (collides with offset 0)? Recommend `null` for unambiguousness.
3. The audit assertion (Risk 1) — gate it behind a debug build flag, or
   always-on? Always-on adds ~1% overhead; flag-gated risks silent drift.
   Default: flag-gated + run-always in CI.
4. Should the snapshot builder's existing `branch_target` field be unified
   with this design (use the same sentinel, same semantics)? They serve
   different purposes but both use `UINT32_MAX = N/A`. Probably no — keep
   them independent to avoid coupling.

---

**Next steps (when this lands):**
- Open a dexllm tracking issue with this doc linked.
- File the dexllm PR for Steps 1–6.
- After merge + version bump, file the dexllm-web PR for Steps 7–8.
- Update `docs/xref.md` to move D-3 from the "blocked" bucket to "landed".
