# D-3: Precise smali ↔ Java line sync — dexllm upstream proposal

**Status:** spec / design — not yet implemented.
**Target repo:** `mobile-threat-hunter/dex-analyzer-for-llm` (the dexllm core).
**Consumer:** dexllm-web (this repo), bucket D-3 in [`docs/xref.md`](xref.md).
**Tracking:** [dexllm#1](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/issues/1).
**Revision history:** v2 (2026-06-24) — three corrections from design review applied.
See [§ Design-review corrections](#design-review-corrections) at the bottom for
what changed vs. the v1 draft and why.

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

File: `native/dad_cpp/basic_blocks.cpp` — **single stamp site**.

Every dex instruction is funneled through `DispatchInstruction(const RawIns& ri, …)`
([`instruction_dispatch.cpp:131`](../../dex-analyzer-for-llm/blob/master/native/dad_cpp/instruction_dispatch.cpp))
which returns one `IRFormPtr` per instruction. `BuildNodeFromBlock`
([`basic_blocks.cpp:544`](../../dex-analyzer-for-llm/blob/master/native/dad_cpp/basic_blocks.cpp))
takes that return value and pushes it into the block's `lins` vector. That
push is the canonical "statement-level IR node was just created" event — one
stamp there covers every IR node that the Writer / JSONWriter ever sees:

```cpp
// basic_blocks.cpp:544 — before
IRFormPtr ir = DispatchInstruction(ri, vmap, gen_ret, payload, exception_type);
if (ir) lins.push_back(std::move(ir));

// after
IRFormPtr ir = DispatchInstruction(ri, vmap, gen_ret, payload, exception_type);
if (ir) {
    ir->source_byte_off = ri.byte_off;          // ← single LoC
    lins.push_back(std::move(ir));
}
```

The opcode handlers in `opcode_ins.cpp` (`AssignConst`, `AssignBinaryExp`,
etc.) receive decoded register strings, NOT the `RawIns` — they can't stamp
themselves even if we wanted them to. The funnel is the only place with both
the IR pointer and the original `RawIns`. **This is what makes Step 2 a
single line rather than ~200.**

For nodes created later by structural transforms (`ShortCircuitStruct` wraps
in `control_flow.cpp`, `IfStruct` follow-block synthesis), inheritance is
explicit: the wrap copies `source_byte_off` from its first content child.
Add this in the same handful of `MakeNode<T>` call sites — bounded list,
all in `control_flow.cpp`.

For genuinely synthetic nodes (NopExpression for a DCE'd block, structural
braces) the default `UINT32_MAX` sentinel stays.

**Sub-statement granularity** — if a future consumer wants per-token offsets
(`a + b * c` as 3 dex ops on one Java line), THAT is when per-handler
stamping in `opcode_ins.cpp` becomes necessary. Until then: YAGNI; the
single-stamp design covers the user-mental-model first-anchor-wins
semantics in Step 3.

### Step 3 — Writer records the map during emit

File: `native/dad_cpp/writer.cpp` + `include/writer.h`.

The Writer's output is `std::ostringstream buffer_` (not a `std::string out_`),
and every emit goes through one chokepoint:

```cpp
// writer.h:64
void Write(std::string_view s) { buffer_ << s; }
```

That's the natural place to count newlines. For the IR-side hook, the
statement-level entry point is `Writer::VisitIns(const IRFormPtr& ins)`
([`writer.cpp:1053`](../../dex-analyzer-for-llm/blob/master/native/dad_cpp/writer.cpp)).
Every `lins[i]` traverses this method; the inner `visit_X(...)` virtuals
receive decomposed pieces (`IRForm* lhs`, `int64_t literal`) that don't
carry `source_byte_off`. **Single record hook, single line-count hook:**

```cpp
class Writer {
    std::ostringstream buffer_;
    uint32_t current_line_ = 1;
    // Lines with no underlying RawIns (closing braces, blank separators)
    // simply don't appear in pc_map_; the consumer treats absence as null.
    std::vector<std::pair<uint32_t /*1-based line*/, uint32_t /*byte_off*/>>
        pc_map_;

    void Write(std::string_view s) {
        for (char c : s) if (c == '\n') ++current_line_;
        buffer_ << s;
    }
};

void Writer::VisitIns(const IRFormPtr& ins) {
    if (ins && ins->source_byte_off != UINT32_MAX
        && (pc_map_.empty() || pc_map_.back().first != current_line_)) {
        pc_map_.emplace_back(current_line_, ins->source_byte_off);
    }
    // ... existing dispatch (unchanged)
}
```

The "don't push if same line already recorded" check preserves
first-anchor-wins semantics — matches the user mental model: line N belongs
to its FIRST observable dex op.

(The `writer.h` header has a stale comment at the top describing a
"dynamic_cast" dispatch design from a previous iteration; the actual
implementation is `WriterImpl : public Visitor` at `writer.cpp:103`. Worth
fixing in the same PR but unrelated to D-3.)

### Step 4 — JSONWriter records the same map (AST sidechannel)

File: `native/dad_cpp/dast.cpp`.

⚠️ **This is NOT an in-node field.** DAD's AST is a nested-list form mirroring
androguard's `process(doAST=True)` output:

```cpp
// dast.cpp:230
return AV::Arr({AV::Str("ExpressionStatement"), std::move(expr)});
//             ["ExpressionStatement", expr]
```

Adding an inline `pc` element would shift every downstream index access by
one and break the "AstValue JSON tree models DAD's nested lists/tuples"
invariant (CLAUDE.md, dexllm root) — the 90–95% e2e parity vs androguard
`process(doAST=True)` is explicitly an asserted property. CLAUDE.md
Behavioral §5 ("don't silently break a documented principle") makes
node-inline a non-starter without an explicit divergence decision.

**Solution: sidechannel map**, same shape as Step 3 but emitted into the AST
result alongside the AST itself, not into the AST node bodies:

```cpp
// dast.cpp — JSONWriter
struct AstResult {
    AstValue ast;
    std::vector<std::pair<uint32_t /*ast_stmt_seq*/, uint32_t /*byte_off*/>>
        pc_map;
};

class JSONWriter {
    uint32_t stmt_seq_ = 0;
    std::vector<std::pair<uint32_t, uint32_t>> pc_map_;
};

// Single hook — every statement-form AST node passes through ins_to_stmt.
AstValue JSONWriter::ins_to_stmt(IRForm* op, bool is_ctor) {
    if (op && op->source_byte_off != UINT32_MAX) {
        pc_map_.emplace_back(stmt_seq_, op->source_byte_off);
    }
    ++stmt_seq_;
    // ... existing transform (unchanged — AST shape is NOT modified)
}
```

The pybind11 / wasm bindings expose `pc_map` as a separate field of the
returned dict, mirroring the text-side `DecompileMethodWithPcMap` shape.

`ast_stmt_seq` is the index of the statement-form AST node within the
method's flattened statement sequence (depth-first pre-order). Consumers
walking the AST keep an independent counter; matching is by sequence index,
not by tree position. If a future consumer needs richer mapping
(stmt → multiple sub-expression offsets), upgrade to
`vector<pair<seq, vector<byte_off>>>` then. YAGNI.

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
| 2. Single stamp at dispatch funnel + control_flow inheritance | ~5 | trivial — bounded sites |
| 3. Writer pc_map (Write chokepoint + VisitIns hook) | ~30 | low |
| 4. JSONWriter pc_map sidechannel (ins_to_stmt hook) | ~30 | low — AST tree unchanged |
| 5. `DecompileMethodWithPcMap` API | ~20 | low |
| 6. pybind11 binding | ~15 | low |
| 7. WASM binding (downstream) | ~15 | low |
| 8. dexllm-web smali pane UI | ~150 | medium — UI layout, scroll math |
| Tests | ~100 | — |
| **Total** | **~365** | one PR per repo |

One dexllm PR (Steps 1–6, ~100 LoC + ~100 LoC tests), one dexllm-web PR
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
- Open a dexllm tracking issue with this doc linked. → done:
  [dexllm#1](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/issues/1)
- File the dexllm PR for Steps 1–6.
- After merge + version bump, file the dexllm-web PR for Steps 7–8.
- Update `docs/xref.md` to move D-3 from the "blocked" bucket to "landed".

---

## Design-review corrections

The v1 draft of this spec (commit `a2337b2`) had three concrete errors that
a follow-up design review against the actual dexllm source caught. All
three were verified in code before the v2 rewrite landed:

### v1 error 1 — Step 2 was claimed to need ~200 sites

v1 said "each opcode handler receives the RawIns, ~200 sites × 1 line each
in `opcode_ins.cpp`". This was wrong — handlers like `AssignConst` /
`AssignBinaryExp` receive decoded register strings, not `RawIns`. Every
instruction funnels through `DispatchInstruction(const RawIns& ri, …)` →
`BuildNodeFromBlock`'s single `lins.push_back(...)` site. v2 replaces the
200-site plan with one stamp at the funnel + a handful of inheritance copies
in `control_flow.cpp` for structural-transform wraps. **LoC: 200 → ~5.**

### v1 error 2 — Step 3 mechanism described a hypothetical Writer

v1 wrote `out_ += '\n'` / `emit_newline()`. Actual Writer state is
`std::ostringstream buffer_` + a single `Write(std::string_view)` chokepoint
at `writer.h:64`. v1 also said "every visit_X calls record_line" — but the
visit_X virtuals receive decomposed pieces (`IRForm* lhs`, `int64_t literal`)
that don't carry `source_byte_off`. The correct hook is the statement-level
funnel `Writer::VisitIns(const IRFormPtr&)` at `writer.cpp:1053`. v2
rewritten accordingly.

### v1 error 3 — Step 4 inline `pc` field broke AST parity

v1 proposed adding `pc` as an object field on AST nodes. DAD's AST is a
nested-list form (`["ExpressionStatement", expr]`, `dast.cpp:230`) mirroring
androguard's `process(doAST=True)` to within 90–95% — inlining `pc` would
shift element indices and break the documented invariant. CLAUDE.md
Behavioral §5 ("don't silently break a documented principle") makes that a
mandatory-stop. v2 moves the AST offsets to a sidechannel map (same shape
as the Writer's `pc_map`), keyed by AST-statement sequence index. AST tree
shape is unchanged.

### What didn't change

- The core idea (stamp on IR construction, harvest at emit time, parity-
  neutral metadata) is sound.
- Steps 5/6/7/8 (public APIs, bindings, UI consumer) stand.
- Acceptance criteria + risk analysis stand.
- Open questions stand; #2 (AST `null` vs `0`) became moot after error 3's
  fix — sidechannel maps have no node-side ambiguity.
