# D-3: Precise smali ↔ Java line sync — dexllm upstream proposal

**Status:** spec / design — not yet implemented.
**Target repo:** `mobile-threat-hunter/dex-analyzer-for-llm` (the dexllm core).
**Consumer:** dexllm-web (this repo), bucket D-3 in [`docs/xref.md`](xref.md).
**Tracking:** [dexllm#1](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/issues/1).
**Revision history:**
- v3 (2026-06-24) — Finding A (conditional/loop/switch headers bypass VisitIns),
  B (no wrap-inheritance needed), C (AST sidechannel key definition).
- v2 (2026-06-24) — three corrections from design review applied.
See [§ Design-review corrections](#design-review-corrections) at the bottom for
diff history.

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
stamp there covers every leaf IR node that the Writer / JSONWriter ever
sees, including the operands inside short-circuit `Condition` wraps:

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

**No wrap-inheritance needed.** Structural wraps (`Condition` from
`ShortCircuitStruct`, `LoopBlock`'s `cond_node`, etc.) don't carry their own
offset; they expose `get_ins()` which concats their child IRs' `get_ins()`
([`basic_blocks.cpp:306`](../../dex-analyzer-for-llm/blob/master/native/dad_cpp/basic_blocks.cpp#L306)):

```cpp
std::vector<IRFormPtr> Condition::get_ins() const {
    auto a = cond1->get_ins();
    auto b = cond2->get_ins();
    a.insert(a.end(), std::make_move_iterator(b.begin()),
             std::make_move_iterator(b.end()));
    return a;
}
```

Step 3's conditional/loop/switch header hooks pull the offset from
`get_ins().back()` (the rightmost dispatch-stamped leaf) instead of relying
on a wrap-level field. Simpler than the v2 wrap-inheritance plan and works
for short-circuit chains of arbitrary depth.

For genuinely synthetic nodes (NopExpression for a DCE'd block, structural
braces) the default `UINT32_MAX` sentinel stays.

**Sub-statement granularity** — if a future consumer wants per-token offsets
(`a + b * c` as 3 dex ops on one Java line), THAT is when per-handler
stamping in `opcode_ins.cpp` becomes necessary. Until then: YAGNI; the
single-stamp design covers the user-mental-model first-anchor-wins
semantics in Step 3.

### Step 3 — Writer records the map at every emit chokepoint

File: `native/dad_cpp/writer.cpp` + `include/writer.h`.

The Writer's output is `std::ostringstream buffer_` ([`writer.h:79`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/include/writer.h#L79)),
and every text emit goes through one method ([`writer.h:64`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/include/writer.h#L64)):

```cpp
void Write(std::string_view s) { buffer_ << s; }
```

That's the natural place to count newlines. Each `'\n'` bumps
`current_line_`. The map is harvested into the result alongside the text.

For IR → line recording, **there is NOT a single chokepoint** — that was a
v2 error. The Writer emits statements via two distinct paths:

| Emit path | Where the IR is observed | Hook needed |
|---|---|---|
| `EmitStatement` / `EmitReturn` / `EmitThrow` (regular stmt lists) | `for (auto& ins : …) VisitIns(ins)` ([`writer.cpp:794/808/812`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/writer.cpp#L794)) | `VisitIns` — ✓ statement chokepoint |
| `EmitIf` (`if (` header) | `cond->visit_cond(wi)` ([`writer.cpp:826/848/879`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/writer.cpp#L826)) | Header hook |
| `EmitLoop` (`while (` / `} while (` headers) | `loop->visit_cond(wi)` / `latch_cond->visit_cond(wi)` ([`writer.cpp:909-969`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/writer.cpp#L909)) | Header hook |
| `EmitSwitch` (`switch (` header) | `lins.back()->Accept(wi)` ([`writer.cpp:981`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/writer.cpp#L981)) | Header hook |

The header paths call `visit_cond(...)` / `Accept(...)` directly on the
condition's operand IR — bypassing `VisitIns`. Without a header hook, the
`if (...)` / `while (...)` / `switch (...)` / `} while (...)` lines get
**zero pc_map entries**. Those are exactly the lines D-3 most needs to
pinpoint — short-circuit conditions packed on one line are the headline
motivation case.

**Implementation:** `record_line(off)` helper called from FOUR sites.
Header sites pull the offset from `CondBlock::get_ins().back()->source_byte_off`
(the rightmost leaf, dispatch-stamped per Step 2; for short-circuit
`Condition` wraps this transparently reaches into the chain via the concat
in `Condition::get_ins()` quoted above).

```cpp
class Writer {
    std::ostringstream buffer_;
    uint32_t current_line_ = 1;
    std::vector<std::pair<uint32_t /*1-based line*/, uint32_t /*byte_off*/>>
        pc_map_;

    void Write(std::string_view s) {
        for (char c : s) if (c == '\n') ++current_line_;
        buffer_ << s;
    }

    // First-anchor-wins per line; absence of a line in the map = consumer
    // renders no offset (closing braces, blank separators).
    void record_line(uint32_t off) {
        if (off == UINT32_MAX) return;
        if (pc_map_.empty() || pc_map_.back().first != current_line_) {
            pc_map_.emplace_back(current_line_, off);
        }
    }

    // Helper that pulls the rightmost stamped leaf offset from a condition
    // expression — `Condition::get_ins()` already concats both arms, and
    // every leaf was stamped at dispatch (Step 2).
    static uint32_t back_offset(const IRFormPtr& ir) {
        if (!ir) return UINT32_MAX;
        auto ins = ir->get_ins();
        if (ins.empty()) return ir->source_byte_off;
        return ins.back()->source_byte_off;
    }
};

void Writer::VisitIns(const IRFormPtr& ins) {
    if (ins) record_line(ins->source_byte_off);
    // ... existing dispatch (unchanged)
}

// EmitIf — three sites where the header is written (the two early-exit
// patterns + the normal `if (` path).
void Writer::EmitIf(CondBlock* cond) {
    // ... existing branch decisions ...
    record_line(back_offset(cond->get_ins().empty()
                              ? nullptr
                              : cond->get_ins().back()));   // ← header line
    Write("if (");
    cond->visit_cond(wi);
    Write(") {\n");
    // ... rest unchanged
}

// EmitLoop — pretest (`while (`) + posttest (`} while (`) + endless
// (`while(true)`) — only the first two have a meaningful operand offset;
// `while(true)` has no condition IR (default UINT32_MAX → no-op).
void Writer::EmitLoop(LoopBlock* loop) {
    // pretest path
    record_line(back_offset_of_cond(loop));
    Write("while (");
    loop->visit_cond(wi);
    // ... posttest mirrors via latch_cond
}

// EmitSwitch
void Writer::EmitSwitch(SwitchBlock* sw) {
    record_line(lins.back()->source_byte_off);
    Write("switch (");
    lins.back()->Accept(wi);
    // ... rest unchanged
}
```

The exact placement is "immediately before the `Write("if (");`/
`Write("while (");`/`Write("switch (");`" so the recorded line is the
header line and not whatever the previous statement ended at.

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

**Solution: sidechannel map keyed by an explicit `node_id`**, written into
the AST result alongside the AST tree itself. The AST tree's nested-list
shape is unchanged — we just emit a parallel `pc_map: [(node_id, byte_off)]`
list, with each AST statement node carrying a fresh integer `node_id` as
its FIRST list element (replacing the kind string with a `[node_id, kind, …]`
prefix is one option but again breaks index access; the cleaner choice is
to NOT modify nodes and instead key the sidechannel by a producer/consumer
shared traversal-order index).

**Recommended key scheme — emit-order index, NOT tree position.** Both the
producer (`JSONWriter`) and the consumer (downstream tools, dexllm-web)
walk the AST in the same pre-order traversal and assign each visited
statement-form node a 0-based sequential index. The producer stores
`pc_map[i] = (i_th_visited_statement, byte_off)`; the consumer matches by
its own counter.

```cpp
// dast.cpp — JSONWriter
struct AstResult {
    AstValue ast;
    std::vector<std::pair<uint32_t /*stmt_emit_seq*/, uint32_t /*byte_off*/>>
        pc_map;
};

class JSONWriter {
    uint32_t stmt_seq_ = 0;
    std::vector<std::pair<uint32_t, uint32_t>> pc_map_;
};

// Hook 1 — regular statement chokepoint.
AstValue JSONWriter::ins_to_stmt(IRForm* op, bool is_ctor) {
    if (op && op->source_byte_off != UINT32_MAX) {
        pc_map_.emplace_back(stmt_seq_, op->source_byte_off);
    }
    ++stmt_seq_;
    // ... existing transform (unchanged)
}

// Hook 2 — visit_cond_node. Conditional headers (`if (...) {`) emit as
// a `["IfStatement", cond_expr, then_body, else_body]` AST node — the
// `cond_expr` is built via visit_condition without going through
// ins_to_stmt. Same blocking problem as Writer's EmitIf.
void JSONWriter::visit_cond_node(CondBlock* cond) {
    auto ins = cond->get_ins();
    if (!ins.empty() && ins.back()->source_byte_off != UINT32_MAX) {
        pc_map_.emplace_back(stmt_seq_, ins.back()->source_byte_off);
    }
    ++stmt_seq_;
    // ... existing transform (unchanged — emits IfStatement node)
}

// Hook 3 — visit_loop_node (same rationale, for WhileStatement /
// DoWhileStatement nodes).
void JSONWriter::visit_loop_node(LoopBlock* loop) { /* mirror */ }

// Hook 4 — visit_switch_node (SwitchStatement).
void JSONWriter::visit_switch_node(SwitchBlock* sw) { /* mirror */ }
```

The pybind11 / wasm bindings expose `pc_map` as a separate field of the
returned dict, mirroring the text-side `DecompileMethodWithPcMap` shape.

**Consumer contract** — every AST consumer that wants pc_map MUST walk the
AST in the SAME order JSONWriter emits: depth-first pre-order, visiting
statement-form nodes (anything created by `ins_to_stmt`, `visit_cond_node`,
`visit_loop_node`, `visit_switch_node`) in source-emit order. Documented
in the producer-side comment so a future schema bump (e.g. switching to
post-order, or interleaving) is caught.

If a future consumer needs richer mapping (stmt → multiple sub-expression
offsets), upgrade to `vector<pair<seq, vector<byte_off>>>` then. YAGNI.

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
3. **Statement-line test.** `tests/test_pc_line_map.py` — decompile a
   hand-picked method, assert (a) every Java line that mentions an invoke /
   iget / sget / new-instance / const-string has a `pc_map` entry,
   (b) the entry's `byte_off` matches the actual smali offset of that op.
4. **Conditional/loop/switch header test** (Finding A guard — MANDATORY).
   `tests/test_pc_line_map_headers.py` — for hand-picked methods that
   contain:
     - a short-circuit condition packed on one line (`(x && y) || z`)
     - a `while (…)` loop header
     - a `do { … } while (…)` posttest header
     - a `switch (…)` header
   assert the corresponding `if (`/`while (`/`} while (`/`switch (` line
   has a `pc_map` entry, and the offset matches the actual `if-*` /
   `*-switch` smali instruction's byte offset. Without this gate, the
   v3 Finding A regression (missing hooks at header emit sites) lands
   green — the headline feature silently degrades to D-2 heuristic for
   the case D-3 was built for.
5. **Audit pass.** Add `tests/test_pc_map_coverage.py` — for every method in
   a corpus subset, walk `pc_map` and verify the offsets correspond to real
   `RawIns` byte offsets in the snapshot.
6. **AST forward-compat.** AST nested-list shape is byte-identical to the
   pre-D-3 output (parity 28/28 still holds). New `pc_map` field is exposed
   as a sibling to the existing AST tree in the result dict — consumers
   that don't request it never see it.

## Estimated effort

| Step | LoC | Risk |
|---|---|---|
| 1. `IRForm` field | 1 | trivial |
| 2. Single stamp at dispatch funnel (no wrap inheritance — `Condition::get_ins()` concats) | ~3 | trivial |
| 3. Writer pc_map (Write chokepoint + VisitIns + EmitIf/Loop/Switch header hooks) | ~50 | low |
| 4. JSONWriter pc_map sidechannel (ins_to_stmt + visit_cond/loop/switch_node hooks) | ~50 | low — AST tree unchanged |
| 5. `DecompileMethodWithPcMap` API | ~20 | low |
| 6. pybind11 binding | ~15 | low |
| 7. WASM binding (downstream) | ~15 | low |
| 8. dexllm-web smali pane UI | ~150 | medium — UI layout, scroll math |
| Tests (incl. mandatory header gate from Finding A) | ~150 | — |
| **Total** | **~450** | one PR per repo |

One dexllm PR (Steps 1–6, ~140 LoC + ~150 LoC tests), one dexllm-web PR
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

### What didn't change in v2

- The core idea (stamp on IR construction, harvest at emit time, parity-
  neutral metadata) is sound.
- Steps 5/6/7/8 (public APIs, bindings, UI consumer) stand.
- Acceptance criteria + risk analysis stand.
- Open questions stand; #2 (AST `null` vs `0`) became moot after error 3's
  fix — sidechannel maps have no node-side ambiguity.

### v3 corrections (2026-06-24, second design-review round)

The v2 spec had three more issues that an emit-path code review caught.
Reproduced verbatim with file:line citations:

#### Finding A (blocking) — emit hook missed conditional / loop / switch headers

v2 said `record_line` runs at `VisitIns` only. But conditional, loop, and
switch HEADERS don't go through `VisitIns` — they're emitted via direct
`visit_cond` / `Accept` calls on the condition operand IR:

| Emit path | Header emit call | Hooked by v2? |
|---|---|---|
| `EmitIf` ([`writer.cpp:826/848/879`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/writer.cpp#L826)) | `cond->visit_cond(wi)` | ❌ |
| `EmitLoop` ([`writer.cpp:909/969`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/writer.cpp#L909)) | `loop->visit_cond(wi)` / `latch_cond->visit_cond(wi)` | ❌ |
| `EmitSwitch` ([`writer.cpp:981`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/writer.cpp#L981)) | `lins.back()->Accept(wi)` | ❌ |

v2 as written would silently produce ZERO pc_map entries for
`if (…)` / `while (…)` / `} while (…)` / `switch (…)` lines — and
short-circuit conditions on one of those lines is the headline D-3
motivation case. Implementing v2 verbatim = the feature doesn't do its
main job.

Same gap on the AST side: `dast.cpp:538/490/591` `visit_cond_node` /
`visit_loop_node` / `visit_switch_node` emit conditions via
`visit_condition` / `visit_expr` and don't pass through `ins_to_stmt`.

**Fix:** hooks at four sites, not one. Text and AST mirror each other.
v3 spec (above) lays them out.

#### Finding B — wrap-inheritance not needed (and turns out simpler that way)

v2 said `ShortCircuitStruct` wraps need to inherit `source_byte_off` from
their first child. Actually `Condition::get_ins()` ([`basic_blocks.cpp:306`](https://github.com/mobile-threat-hunter/dex-analyzer-for-llm/blob/master/native/dad_cpp/basic_blocks.cpp#L306))
already concats both arms' `get_ins()`. Each leaf is dispatch-stamped per
Step 2. The Finding A header hook can pull from `cond->get_ins().back()`
and get the right answer for short-circuit chains of arbitrary depth — no
wrap-level field needed. v3 drops the wrap-inheritance plan from Step 2;
control_flow.cpp doesn't need to touch.

#### Finding C — AST sidechannel key underspecified

v2 wrote "key by AST-statement sequence index" but didn't define what
that index is (DFS pre-order? tree position? source-emit order?). With
Finding A landing additional non-`ins_to_stmt` hook sites
(`visit_cond_node` etc.), an under-specified key is more likely to drift
between producer and consumer.

**Fix:** v3 spec (above) explicitly names the key as **statement-emit
sequence index** — both sides walk the AST pre-order in JSONWriter's emit
order, incrementing a shared 0-based counter at each statement-form node
(everything that goes through `ins_to_stmt`, `visit_cond_node`,
`visit_loop_node`, or `visit_switch_node`). Documented in the
producer-side comment so a future schema change is caught.
