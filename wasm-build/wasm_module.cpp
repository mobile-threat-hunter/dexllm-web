// wasm_module.cpp — embind binding mirroring native/binding/module.cpp's PyDexKit
// for the dexllm-web in-browser demo. Single-threaded WASM build (GitHub Pages
// can't serve the COOP/COEP headers SharedArrayBuffer needs).
//
// JS API (mirrors index.html's expectations):
//   class WasmDexKit
//     ctor(path: string)                       // single-source load
//     dexCount(): number
//     verifyReport(): Array<{dex_id,name,valid,reason}>
//     listClasses(): VectorString
//     listClassMethods(cls): VectorString
//     decompileClassJava(cls): string
//     decompileMethodJava(desc): string
//     listValueStrings(): VectorString           // (was listStrings — dexllm 0.1.6+)
//     listExternalTypeRefs(): VectorString
//     listExternalMethodRefs(): Array<{cls,name,proto}>
//     xrefStringsToClasses(VectorString): Array<Array<string>>
//     findCallSitesToApi(desc): VectorString
//
// All vectors registered as register_vector<std::string> (name "VectorString").

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "api_ref.h"
#include "decompiler.h"
#include "dexitem_code_source.h"
#include "dexkit_ext.h"
#include "dex_item.h"      // for GetReader, GetStrings, GetImage
#include "slicer/reader.h" // dex::ClassDef, dataPtr, ClassDefs

using emscripten::class_;
using emscripten::function;
using emscripten::register_vector;
using emscripten::val;

namespace {

// ── encoded_array scanners — siblings of the anonymous-namespace helpers in
//    DexKitExt::ListValueStrings (native/core_ext/dexkit_ext.cpp). Mirrored
//    here so the WASM binding can ask "which class's static_values include
//    THIS string?" — the question dexllm proper never had to answer (its IoC
//    pipeline takes the union and tags via L7 method-code search, which by
//    construction misses fields). Re-implemented locally rather than promoted
//    to DexKitExt so the upstream dexllm change set stays empty.
uint64_t WasmScanUleb(const uint8_t*& p, const uint8_t* end) {
    uint64_t result = 0; int shift = 0;
    while (p < end && shift < 64) {
        uint8_t b = *p++;
        result |= static_cast<uint64_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}
uint64_t WasmScanIntLE(const uint8_t*& p, const uint8_t* end, std::size_t nbytes) {
    uint64_t v = 0;
    for (std::size_t i = 0; i < nbytes && p < end; ++i)
        v |= static_cast<uint64_t>(*p++) << (i * 8);
    return v;
}
// Walk one encoded_value; for VALUE_STRING (0x17) push the string index.
// Recurse through ARRAY (0x1c) + ANNOTATION (0x1d) — all other types only
// advance the cursor by their payload (idx/number = value_arg+1 bytes;
// NULL/BOOLEAN 0).
void WasmScanEncodedValueStrings(const uint8_t*& p, const uint8_t* end,
                                 std::vector<uint32_t>& out) {
    if (p >= end) return;
    uint8_t header = *p++;
    uint8_t value_arg = (header >> 5) & 0x07;
    uint8_t value_type = header & 0x1F;
    std::size_t nbytes = static_cast<std::size_t>(value_arg) + 1;
    switch (value_type) {
        case 0x17:
            out.push_back(static_cast<uint32_t>(WasmScanIntLE(p, end, nbytes)));
            return;
        case 0x1c: {
            uint64_t sz = WasmScanUleb(p, end);
            for (uint64_t i = 0; i < sz && p < end; ++i)
                WasmScanEncodedValueStrings(p, end, out);
            return;
        }
        case 0x1d: {
            (void)WasmScanUleb(p, end);
            uint64_t sz = WasmScanUleb(p, end);
            for (uint64_t i = 0; i < sz && p < end; ++i) {
                (void)WasmScanUleb(p, end);
                WasmScanEncodedValueStrings(p, end, out);
            }
            return;
        }
        case 0x1e: case 0x1f: return;
        default: {
            std::size_t avail = static_cast<std::size_t>(p < end ? end - p : 0);
            p += std::min(nbytes, avail);
            return;
        }
    }
}

class WasmDexKit {
public:
    explicit WasmDexKit(const std::string& path)
        : ext_(path, /*lenient=*/false),
          decompiler_(std::make_unique<dexkit::dad::Decompiler>(
              ext_.GetCodeSource())) {}

    // Multi-source ctor — drives the packer / runtime-dump workflow. Sources
    // are loaded IN ORDER (earlier → lower dex_id → wins class collisions per
    // ART's first-wins resolution). The JS caller lists dumps BEFORE the apk
    // so dumped classes win. lenient=true verifies in ART-structural-equivalent
    // mode so a partially-decrypted dump still loads.
    WasmDexKit(const std::vector<std::string>& sources, bool lenient)
        : ext_(sources, lenient),
          decompiler_(std::make_unique<dexkit::dad::Decompiler>(
              ext_.GetCodeSource())) {}

    int dexCount() const { return ext_.DexCount(); }

    // Source list the instance was loaded from (single path → length 1).
    std::vector<std::string> sources() const { return ext_.GetSources(); }

    // dex_id where the class is declared, or -1 if it's external. Drives the
    // per-dex view filter on the JS side.
    int locateClassDex(const std::string& descriptor) const {
        return ext_.LocateClassDex(descriptor);
    }

    val verifyReport() const {
        val arr = val::array();
        std::size_t i = 0;
        for (const auto& s : ext_.VerifyReport()) {
            val o = val::object();
            o.set("dex_id", s.dex_id);
            o.set("name", s.name);
            o.set("valid", s.valid);
            o.set("reason", s.reason);
            arr.set(i++, o);
        }
        return arr;
    }

    std::vector<std::string> listClasses() const {
        return ext_.ListClasses();
    }

    // Every class declared in ONE specific dex — no first-wins dedup. Returns
    // the duplicates the global ListClasses also returns for that dex but in
    // isolation, so the per-dex UI tab can show a class that lost the global
    // first-wins resolution (e.g. an encrypted version inside the original APK
    // that's also present, decrypted, in a dumped dex loaded with priority).
    // Walks the DexItem's TypeDefFlags directly to avoid the upstream
    // class_declare_dex_map's first-wins gate.
    std::vector<std::string> listClassesInDex(int dex_id) const {
        std::vector<std::string> out;
        if (dex_id < 0) return out;
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        const int n = mut.DexCount();
        if (dex_id >= n) return out;
        // We need the same walk as DexKitExt::ListClasses but for ONE dex_id.
        // dex_id is a valid loaded dex (dexCount-bounded).
        auto* item = mut.core().GetDexItem(static_cast<uint16_t>(dex_id));
        if (item == nullptr) return out;
        const auto& type_names = item->GetTypeNames();
        const auto& flags      = item->GetTypeDefFlags();
        out.reserve(flags.size());
        for (std::size_t type_idx = 0; type_idx < flags.size(); ++type_idx) {
            if (!flags[type_idx]) continue;
            out.emplace_back(type_names[type_idx]);
        }
        return out;
    }

    std::vector<std::string>
    listClassMethods(const std::string& cls) const {
        return ext_.ListClassMethods(cls);
    }

    // baksmali-style text rendering of a single method body. Each invoke-*
    // instruction carries the FULL `Lcls;->name(proto)Ret` of its target, so
    // smali is the bytecode-faithful answer to "what does this method actually
    // call?" — no decompiler text inference needed. Wired into the JS click
    // handler so a click on `v0_1.method()` resolves to the precise callee.
    std::string renderMethodSmali(const std::string& descriptor) const {
        try { return ext_.RenderMethodSmali(descriptor); }
        catch (const std::exception& e) {
            return std::string("; SMALI ERROR: ") + e.what() + "\n";
        } catch (...) {
            return "; SMALI ERROR: unknown C++ exception\n";
        }
    }

    // Decompile-side belt-and-suspenders. dexllm's Decompiler::DecompileMethod
    // catches std::exception internally and yields a `// DECOMPILE ERROR:`
    // line, but DecompileClass's outer iteration and any throws from
    // MethodSnapshotBuilder / DvClass::get_source weren't guarded. Under
    // -fexceptions those bubbled out as raw CppExceptions whose freed-pointer
    // is unreadable from JS — the user saw "wasm exception (excPtr=N)" with
    // no class body. Wrap both entry points: a caught throw becomes a
    // visible "// DECOMPILE ERROR: <what()>" so the user sees the cause,
    // and the decompile result still lands in the viewer.
    std::string decompileClassJava(const std::string& cls) const {
        try { return decompiler_->DecompileClass(cls); }
        catch (const std::exception& e) {
            return std::string("// DECOMPILE ERROR: ") + e.what() + "\n";
        } catch (...) {
            return "// DECOMPILE ERROR: unknown C++ exception\n";
        }
    }

    std::string decompileMethodJava(const std::string& desc) const {
        try { return decompiler_->DecompileMethod(desc); }
        catch (const std::exception& e) {
            return std::string("// DECOMPILE ERROR: ") + e.what() + "\n";
        } catch (...) {
            return "// DECOMPILE ERROR: unknown C++ exception\n";
        }
    }

    // D-3 (dexllm#1) — text + (java_line ↔ dex byte offset) map. Drives the
    // dexllm-web smali-sync pane: each Java line that came from a real dex
    // instruction carries its bytecode offset; the JS side cross-references
    // against the smali render to scroll/glow the matching invoke / iget /
    // if-* / switch instruction.
    val decompileMethodJavaWithPc(const std::string& desc) const {
        val obj = val::object();
        try {
            auto r = decompiler_->DecompileMethodWithPcMap(desc);
            obj.set("source", r.source);
            val arr = val::array();
            std::size_t i = 0;
            for (const auto& [line, off] : r.pc_map) {
                val o = val::object();
                o.set("line", static_cast<int>(line));
                o.set("offset", static_cast<int>(off));
                arr.set(i++, o);
            }
            obj.set("pcMap", arr);
        } catch (const std::exception& e) {
            obj.set("source", std::string("// DECOMPILE ERROR: ") + e.what() + "\n");
            obj.set("pcMap", val::array());
        } catch (...) {
            obj.set("source", std::string("// DECOMPILE ERROR: unknown\n"));
            obj.set("pcMap", val::array());
        }
        return obj;
    }

    // VALUE strings only — `const-string` operands + static-field VALUE_STRING
    // initializers (MUTF-8 → UTF-8 in DexKitExt). The old whole-pool
    // `list_strings()` was removed upstream; only IOC used it and identifier
    // noise (type/method/field names) was the issue.
    std::vector<std::string> listValueStrings() const {
        return ext_.ListValueStrings();
    }

    // Distinct external type DESCRIPTORS — we drop the per-ref dex-id list
    // since the IOC pipeline only needs descriptors to compute dex-package
    // prefixes for denoise.
    std::vector<std::string> listExternalTypeRefs() const {
        const bool framework_only = false;
        std::vector<std::string> out;
        for (const auto& r : ext_.ListExternalTypeRefs(framework_only)) {
            out.push_back(r.descriptor);
        }
        return out;
    }

    // Every external method ref as {cls, name, proto}. JS-side joins these
    // against the dangerous-permission table (signature-precise: arity primary,
    // simple-type tiebreak — see index.html computePerms).
    val listExternalMethodRefs() const {
        const bool framework_only = false;
        val arr = val::array();
        std::size_t i = 0;
        for (const auto& r : ext_.ListExternalMethodRefs(framework_only)) {
            val o = val::object();
            o.set("cls", r.class_descriptor);
            o.set("name", r.name);
            o.set("proto", r.proto);
            arr.set(i++, o);
        }
        return arr;
    }

    // Scan every loaded dex's class static_values for a string-equal match and
    // return the descriptors of the declaring classes. Plugs the IoC gap:
    // xrefStringsToClasses uses method-code search (Aho-Corasick over const-
    // string operands), so a value present ONLY in a static-field VALUE_STRING
    // initializer (e.g. `String API = "http://evil.com";`) gets zero hits there.
    // This walks each ClassDef's static_values_off encoded_array directly,
    // recursing through ARRAY (0x1c) / ANNOTATION (0x1d) entries, and stops at
    // the first matching VALUE_STRING per class so we don't double-list.
    // Return the raw bytes of one loaded dex by global dex_id. The dexllm-web
    // Standalone mode uses this to extract each classes*.dex from the source
    // APK and create a TRULY isolated WasmDexKit per dex — no first-wins, no
    // aggregation. Without isolation, the IoC and dangerous-perm panels would
    // pool every source's data; the user wants each tab to show only its own
    // dex's indicators.
    //
    // Returns a typed_memory_view aliasing the dex's MemMap — the caller
    // MUST `new Uint8Array(view)` immediately to copy out, before any
    // subsequent wasm allocation invalidates the view.
    val extractDexBytes(int dex_id) const {
        if (dex_id < 0) return val::null();
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        if (dex_id >= mut.DexCount()) return val::null();
        auto* item = mut.core().GetDexItem(static_cast<uint16_t>(dex_id));
        if (item == nullptr) return val::null();
        auto* img = item->GetImage();
        if (img == nullptr) return val::null();
        return val(emscripten::typed_memory_view(
            img->len(), reinterpret_cast<const uint8_t*>(img->data())));
    }

    std::vector<std::string>
    findClassesWithStaticValueString(const std::string& value) const {
        std::vector<std::string> out;
        std::unordered_set<std::string> seen;
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        auto& core = mut.core();
        const int n = mut.DexCount();
        for (int i = 0; i < n; ++i) {
            auto* item = core.GetDexItem(static_cast<uint16_t>(i));
            if (item == nullptr) continue;
            const auto& strings    = item->GetStrings();
            const auto& type_names = item->GetTypeNames();
            const auto& reader     = item->GetReader();
            const uint8_t* mmap_end = nullptr;
            if (auto* img = item->GetImage())
                mmap_end = reinterpret_cast<const uint8_t*>(img->data()) + img->len();
            for (const auto& cdef : reader.ClassDefs()) {
                if (cdef.static_values_off == 0) continue;
                const uint8_t* p = reader.dataPtr<uint8_t>(cdef.static_values_off);
                if (p == nullptr) continue;
                const uint8_t* end = mmap_end ? mmap_end : p + (1u << 20);
                if (p >= end) continue;
                uint64_t count = WasmScanUleb(p, end);
                std::vector<uint32_t> ids;
                for (uint64_t k = 0; k < count && p < end; ++k)
                    WasmScanEncodedValueStrings(p, end, ids);
                for (uint32_t sid : ids) {
                    if (sid < strings.size() &&
                        std::string_view(strings[sid]) == value) {
                        std::string desc(type_names[cdef.class_idx]);
                        if (seen.insert(desc).second) out.push_back(std::move(desc));
                        break;   // one hit per class is enough
                    }
                }
            }
        }
        return out;
    }

    // Batched L7 string-xref. For each input value, returns the list of class
    // descriptors referencing it. One BatchFindClassesUsingStrings pass over
    // a shared Aho-Corasick trie (cheap vs N independent passes).
    val xrefStringsToClasses(const std::vector<std::string>& values) {
        std::map<std::string, std::vector<std::string>> q;
        for (std::size_t i = 0; i < values.size(); ++i) {
            // Unique synthetic key per input slot so duplicate values keep
            // their own bucket; we re-key by index when reading back below.
            q[std::to_string(i)] = std::vector<std::string>{values[i]};
        }
        auto hits = ext_.BatchFindClassesUsingStrings(q, "contains", false);
        val arr = val::array();
        for (std::size_t i = 0; i < values.size(); ++i) {
            val inner = val::array();
            auto it = hits.find(std::to_string(i));
            if (it != hits.end()) {
                std::size_t j = 0;
                for (const auto& m : it->second) {
                    inner.set(j++, val(m.descriptor));
                }
            }
            arr.set(i, inner);
        }
        return arr;
    }

    // Every caller method descriptor invoking the given API. Drives the JS-
    // side dangerous-permission caller resolution (L2). Idempotent — caches
    // warm on first call (`WarmAnalysisCaches` implied by the upstream API).
    std::vector<std::string>
    findCallSitesToApi(const std::string& api_descriptor) {
        std::vector<std::string> out;
        for (const auto& cs : ext_.FindCallSitesToApi(api_descriptor)) {
            out.push_back(cs.caller_descriptor);
        }
        return out;
    }

    // Same query, richer return — exposes each call site's bytecode offset
    // so the JS-side callers popup can distinguish multiple invocations from
    // the SAME caller method (foo() called bar() twice → two separate rows
    // with their own offsets, not silently deduped). The offset is the L2.5
    // value dexkit fills in; -1 sentinels mean the upstream didn't have it
    // (rare; the JS treats `-1` as "unknown" and renders without offset).
    val findCallSitesWithOffset(const std::string& api_descriptor) {
        val arr = val::array();
        std::size_t i = 0;
        for (const auto& cs : ext_.FindCallSitesToApi(api_descriptor)) {
            val o = val::object();
            o.set("caller", cs.caller_descriptor);
            o.set("offset", static_cast<int>(cs.bytecode_offset));
            arr.set(i++, o);
        }
        return arr;
    }

    // ── field xref. dexkit carries L2.5 reverse maps `field_get_method_ids`
    // and `field_put_method_ids` keyed by field_idx — exact, instruction-faithful
    // (iget*/sget* vs iput*/sput*), so the JS side can distinguish READERS from
    // WRITERS of a clicked field declaration. Field DESCRIPTORS are the
    // `Lcls;->name:Type` form (matches dexkit's GetFieldDescriptor).
    //
    // Lookup parses the class part, locates the declaring dex via the same
    // first-wins map findCallSitesToApi uses, walks the dex's TypeNames to
    // get type_idx, and matches `GetFieldDescriptor(fid)` against the input
    // across that class's field_ids. Returns {-1, 0} on miss.

    std::vector<std::string>
    listClassFieldDescriptors(const std::string& cls) const {
        std::vector<std::string> out;
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        int dex_id = mut.LocateClassDex(cls);
        if (dex_id < 0) return out;
        auto* item = mut.core().GetDexItem(static_cast<uint16_t>(dex_id));
        if (item == nullptr) return out;
        const auto& type_names = item->GetTypeNames();
        for (uint32_t type_idx = 0; type_idx < type_names.size(); ++type_idx) {
            if (type_names[type_idx] == cls) {
                for (uint32_t fid : item->GetClassFieldIds(type_idx)) {
                    out.emplace_back(BuildFieldDescriptor(*item, fid));
                }
                break;
            }
        }
        return out;
    }

    std::vector<std::string>
    findFieldGetMethods(const std::string& field_descriptor) {
        auto loc = LocateField(field_descriptor);
        if (loc.first < 0) return {};
        ext_.WarmAnalysisCaches();
        auto* item = ext_.core().GetDexItem(static_cast<uint16_t>(loc.first));
        std::vector<std::string> out;
        for (const auto& bean : item->FieldGetMethods(loc.second)) {
            out.emplace_back(bean.dex_descriptor);
        }
        return out;
    }

    std::vector<std::string>
    findFieldPutMethods(const std::string& field_descriptor) {
        auto loc = LocateField(field_descriptor);
        if (loc.first < 0) return {};
        ext_.WarmAnalysisCaches();
        auto* item = ext_.core().GetDexItem(static_cast<uint16_t>(loc.first));
        std::vector<std::string> out;
        for (const auto& bean : item->FieldPutMethods(loc.second)) {
            out.emplace_back(bean.dex_descriptor);
        }
        return out;
    }

    // ── class hierarchy & type-reference xref (bucket A — JEB/jadx parity).
    // All thin wrappers over dexkit primitives the JS side hasn't been able
    // to reach yet.

    // Subclasses (extends-equals) and implementors (interface-implements).
    // The JS-side class hierarchy popup unions both for the "↓ subtypes"
    // section: a class can be a subclass, an interface can have implementors.
    std::vector<std::string>
    findClassesBySuperclass(const std::string& super_cls) {
        std::vector<std::string> out;
        for (const auto& m : ext_.FindClassesBySuperclass(super_cls, "equals")) {
            out.emplace_back(m.descriptor);
        }
        return out;
    }

    std::vector<std::string>
    findClassesImplementing(const std::string& iface_cls) {
        std::vector<std::string> out;
        for (const auto& m : ext_.FindClassesImplementing(iface_cls, "equals")) {
            out.emplace_back(m.descriptor);
        }
        return out;
    }

    // Direct super class + interface_list for `cls`. Walks the slicer
    // ClassDef directly (dexkit doesn't expose a typed accessor). Returns
    // `{super, interfaces[]}` — super is "" when the class isn't loaded or
    // when it's `Ljava/lang/Object;` declared without a parent.
    val getClassSuperAndInterfaces(const std::string& cls) {
        val obj = val::object();
        obj.set("super", std::string());
        obj.set("interfaces", val::array());
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        int dex_id = mut.LocateClassDex(cls);
        if (dex_id < 0) return obj;
        auto* item = mut.core().GetDexItem(static_cast<uint16_t>(dex_id));
        if (item == nullptr) return obj;
        const auto& type_names = item->GetTypeNames();
        const auto& reader = item->GetReader();
        // type_idx for `cls`
        uint32_t type_idx = 0; bool found = false;
        for (uint32_t i = 0; i < type_names.size(); ++i) {
            if (type_names[i] == cls) { type_idx = i; found = true; break; }
        }
        if (!found) return obj;
        // Walk ClassDefs to find this class
        for (const auto& cdef : reader.ClassDefs()) {
            if (cdef.class_idx != type_idx) continue;
            // super
            if (cdef.superclass_idx != dex::kNoIndex &&
                cdef.superclass_idx < type_names.size()) {
                obj.set("super", std::string(type_names[cdef.superclass_idx]));
            }
            // interfaces
            if (cdef.interfaces_off != 0) {
                const auto* type_list = reader.dataPtr<dex::TypeList>(cdef.interfaces_off);
                if (type_list) {
                    val ifaces = val::array();
                    const auto* type_ids = reader.TypeIds().begin();
                    for (uint32_t k = 0; k < type_list->size; ++k) {
                        uint32_t tid = type_list->list[k].type_idx;
                        if (tid < type_names.size()) {
                            ifaces.set(k, std::string(type_names[tid]));
                        }
                    }
                    (void)type_ids;
                    obj.set("interfaces", ifaces);
                }
            }
            break;
        }
        return obj;
    }

    // Where is a type X referenced — at the SIGNATURE level. Walks every
    // loaded dex's FieldIds / MethodIds tables and matches the type_idx.
    // Cheap (no body inspection); captures field types, method return
    // types, method params, and the synthesized super/interface lists.
    // Internal-body uses (instanceof / check-cast / new) require smali
    // walk; those are deferred (would require per-method render).
    val findTypeReferences(const std::string& type_descriptor) {
        val out = val::object();
        val fields = val::array();
        val methodsReturning = val::array();
        val methodsWithParam = val::array();
        std::size_t fi = 0, mri = 0, mpi = 0;
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        for (int d = 0; d < mut.DexCount(); ++d) {
            auto* item = mut.core().GetDexItem(static_cast<uint16_t>(d));
            if (item == nullptr) continue;
            const auto& type_names = item->GetTypeNames();
            uint32_t type_idx = 0; bool found = false;
            for (uint32_t i = 0; i < type_names.size(); ++i) {
                if (type_names[i] == type_descriptor) { type_idx = i; found = true; break; }
            }
            if (!found) continue;
            const auto& reader = item->GetReader();
            const auto& strings = item->GetStrings();
            // Field IDs — match if field.type_idx == type_idx.
            const auto& field_ids = reader.FieldIds();
            for (uint32_t fid = 0; fid < field_ids.size(); ++fid) {
                if (field_ids[fid].type_idx != type_idx) continue;
                std::string desc(type_names[field_ids[fid].class_idx]);
                desc += "->";
                desc += strings[field_ids[fid].name_idx];
                desc += ":";
                desc += type_names[type_idx];
                fields.set(fi++, desc);
            }
            // Method IDs — walk proto_ids and check return + param types.
            const auto& method_ids = reader.MethodIds();
            const auto& proto_ids = reader.ProtoIds();
            // proto_type_list[proto_idx] is a TypeList* of params.
            for (uint32_t mid = 0; mid < method_ids.size(); ++mid) {
                const auto& mdef = method_ids[mid];
                const auto& pdef = proto_ids[mdef.proto_idx];
                // Return type
                bool returns = (pdef.return_type_idx == type_idx);
                // Param types
                bool paramMatch = false;
                if (pdef.parameters_off != 0) {
                    const auto* type_list = reader.dataPtr<dex::TypeList>(pdef.parameters_off);
                    if (type_list) {
                        for (uint32_t k = 0; k < type_list->size; ++k) {
                            if (type_list->list[k].type_idx == type_idx) { paramMatch = true; break; }
                        }
                    }
                }
                if (!returns && !paramMatch) continue;
                // Build the method descriptor — same shape DexItem::GetMethodDescriptor uses.
                std::string desc(type_names[mdef.class_idx]);
                desc += "->";
                desc += strings[mdef.name_idx];
                desc += "(";
                if (pdef.parameters_off != 0) {
                    const auto* type_list = reader.dataPtr<dex::TypeList>(pdef.parameters_off);
                    if (type_list) {
                        for (uint32_t k = 0; k < type_list->size; ++k) {
                            desc += type_names[type_list->list[k].type_idx];
                        }
                    }
                }
                desc += ")";
                desc += type_names[pdef.return_type_idx];
                if (returns) methodsReturning.set(mri++, desc);
                if (paramMatch) methodsWithParam.set(mpi++, desc);
            }
            // Only need one dex's pass — type_names is unique per dex but
            // refs in OTHER dexes also count, so don't break early.
        }
        out.set("fields", fields);
        out.set("methodsReturning", methodsReturning);
        out.set("methodsWithParam", methodsWithParam);
        return out;
    }

    // Methods using a specific string literal (const-string operand).
    // Wraps BatchFindMethodsUsingStrings with a 1-element query so the JS
    // side gets a flat method-descriptor list.
    std::vector<std::string>
    findMethodsUsingString(const std::string& value) {
        std::map<std::string, std::vector<std::string>> q;
        q["v"] = std::vector<std::string>{value};
        auto hits = ext_.BatchFindMethodsUsingStrings(q, "equals", false);
        std::vector<std::string> out;
        auto it = hits.find("v");
        if (it == hits.end()) return out;
        for (const auto& m : it->second) out.emplace_back(m.descriptor);
        return out;
    }

    // Every method descriptor across every loaded dex — drives the JS-side
    // global symbol search (Ctrl+P). One wasm call instead of N×listClassMethods.
    std::vector<std::string>
    listAllMethodDescriptors() const {
        std::vector<std::string> out;
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        for (int d = 0; d < mut.DexCount(); ++d) {
            auto* item = mut.core().GetDexItem(static_cast<uint16_t>(d));
            if (item == nullptr) continue;
            const auto& reader = item->GetReader();
            const auto& type_names = item->GetTypeNames();
            const auto& strings = item->GetStrings();
            const auto& method_ids = reader.MethodIds();
            const auto& proto_ids = reader.ProtoIds();
            for (uint32_t mid = 0; mid < method_ids.size(); ++mid) {
                const auto& mdef = method_ids[mid];
                const auto& pdef = proto_ids[mdef.proto_idx];
                std::string desc(type_names[mdef.class_idx]);
                desc += "->";
                desc += strings[mdef.name_idx];
                desc += "(";
                if (pdef.parameters_off != 0) {
                    const auto* type_list = reader.dataPtr<dex::TypeList>(pdef.parameters_off);
                    if (type_list) {
                        for (uint32_t k = 0; k < type_list->size; ++k) {
                            desc += type_names[type_list->list[k].type_idx];
                        }
                    }
                }
                desc += ")";
                desc += type_names[pdef.return_type_idx];
                out.emplace_back(std::move(desc));
            }
        }
        return out;
    }

    // Every field descriptor across every loaded dex — global symbol search.
    std::vector<std::string>
    listAllFieldDescriptors() const {
        std::vector<std::string> out;
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        for (int d = 0; d < mut.DexCount(); ++d) {
            auto* item = mut.core().GetDexItem(static_cast<uint16_t>(d));
            if (item == nullptr) continue;
            const auto& reader = item->GetReader();
            const auto& field_ids = reader.FieldIds();
            for (uint32_t fid = 0; fid < field_ids.size(); ++fid) {
                out.emplace_back(BuildFieldDescriptor(*item, fid));
            }
        }
        return out;
    }

private:
    // GetFieldDescriptor is private in DexItem; rebuild from the public
    // GetReader/GetTypeNames/GetStrings accessors — same join dex_item.cpp's
    // GetFieldDescriptor does (`Lcls;->name:Type`).
    static std::string
    BuildFieldDescriptor(dexkit::DexItem& item, uint32_t fid) {
        const auto& reader     = item.GetReader();
        const auto& type_names = item.GetTypeNames();
        const auto& strings    = item.GetStrings();
        const auto& field_id   = reader.FieldIds()[fid];
        const auto& type_id    = reader.TypeIds()[field_id.type_idx];
        std::string out(type_names[field_id.class_idx]);
        out += "->";
        out += strings[field_id.name_idx];
        out += ":";
        out += strings[type_id.descriptor_idx];
        return out;
    }

    std::pair<int, uint32_t>
    LocateField(const std::string& field_descriptor) const {
        auto arrow = field_descriptor.find("->");
        if (arrow == std::string::npos) return {-1, 0};
        std::string cls(field_descriptor.substr(0, arrow));
        auto& mut = const_cast<dexkit::ext::DexKitExt&>(ext_);
        int dex_id = mut.LocateClassDex(cls);
        if (dex_id < 0) return {-1, 0};
        auto* item = mut.core().GetDexItem(static_cast<uint16_t>(dex_id));
        if (item == nullptr) return {-1, 0};
        const auto& type_names = item->GetTypeNames();
        for (uint32_t type_idx = 0; type_idx < type_names.size(); ++type_idx) {
            if (type_names[type_idx] == cls) {
                for (uint32_t fid : item->GetClassFieldIds(type_idx)) {
                    if (BuildFieldDescriptor(*item, fid) == field_descriptor) {
                        return {dex_id, fid};
                    }
                }
                break;
            }
        }
        return {-1, 0};
    }

    dexkit::ext::DexKitExt ext_;
    std::unique_ptr<dexkit::dad::Decompiler> decompiler_;
};

}  // namespace

EMSCRIPTEN_BINDINGS(dexllm_wasm) {
    register_vector<std::string>("VectorString");

    class_<WasmDexKit>("WasmDexKit")
        .constructor<std::string>()
        .constructor<std::vector<std::string>, bool>()
        .function("dexCount",              &WasmDexKit::dexCount)
        .function("sources",               &WasmDexKit::sources)
        .function("locateClassDex",        &WasmDexKit::locateClassDex)
        .function("verifyReport",          &WasmDexKit::verifyReport)
        .function("listClasses",           &WasmDexKit::listClasses)
        .function("listClassesInDex",      &WasmDexKit::listClassesInDex)
        .function("listClassMethods",      &WasmDexKit::listClassMethods)
        .function("decompileClassJava",    &WasmDexKit::decompileClassJava)
        .function("decompileMethodJava",   &WasmDexKit::decompileMethodJava)
        .function("decompileMethodJavaWithPc", &WasmDexKit::decompileMethodJavaWithPc)
        .function("renderMethodSmali",     &WasmDexKit::renderMethodSmali)
        .function("listValueStrings",      &WasmDexKit::listValueStrings)
        .function("listExternalTypeRefs",  &WasmDexKit::listExternalTypeRefs)
        .function("listExternalMethodRefs",&WasmDexKit::listExternalMethodRefs)
        .function("xrefStringsToClasses",  &WasmDexKit::xrefStringsToClasses)
        .function("findClassesWithStaticValueString",
                  &WasmDexKit::findClassesWithStaticValueString)
        .function("extractDexBytes",       &WasmDexKit::extractDexBytes)
        .function("findCallSitesToApi",    &WasmDexKit::findCallSitesToApi)
        .function("findCallSitesWithOffset", &WasmDexKit::findCallSitesWithOffset)
        .function("listClassFieldDescriptors", &WasmDexKit::listClassFieldDescriptors)
        .function("findFieldGetMethods",   &WasmDexKit::findFieldGetMethods)
        .function("findFieldPutMethods",   &WasmDexKit::findFieldPutMethods)
        .function("findClassesBySuperclass", &WasmDexKit::findClassesBySuperclass)
        .function("findClassesImplementing", &WasmDexKit::findClassesImplementing)
        .function("getClassSuperAndInterfaces", &WasmDexKit::getClassSuperAndInterfaces)
        .function("findTypeReferences",    &WasmDexKit::findTypeReferences)
        .function("findMethodsUsingString",&WasmDexKit::findMethodsUsingString)
        .function("listAllMethodDescriptors", &WasmDexKit::listAllMethodDescriptors)
        .function("listAllFieldDescriptors",  &WasmDexKit::listAllFieldDescriptors);
}
