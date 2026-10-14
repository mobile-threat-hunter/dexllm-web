// web_analysis.h — the IoC / content-provider / capability engine ports.
//
// VENDORED from dexllm native/core_ext/include/analysis.h at commit c3ec1a1.
// dexllm 4b085d8 removed these from its core: dexllm's own API uses the
// canonical pure-Python dexllm.ioc / providers / capability, so the C++ mirrors
// were web-only and the dependency direction (web -> dexllm) made hosting them
// in dexllm's core an inversion. The decoupling was intentional and dexllm's
// commit message directs WASM consumers to vendor their own engine.
//
// Declarations are byte-faithful to c3ec1a1 so the shared-implementation parity
// claims below still describe this code. PermissionCallers is NOT here — it
// stayed in dexllm's core analysis.h, which this header includes.

#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "analysis.h"  // dexllm core: DexKitExt fwd decl + PermissionCallers

namespace dexkit::ext {

// ---------------------------------------------------------------------------
// IoC extraction (issue #13) — C++ port of dexllm.ioc.extract_iocs, so the WASM
// (embind) and pybind bindings share ONE implementation over the bundled public-
// suffix data (public_suffix.cpp / gen/psl_data.h) instead of dexllm-web
// re-implementing the scan + shipping its own PSL copy. Byte-identical to the
// Python path (verified by a full-corpus differential test).

// One network indicator and the methods that reference it (the "where in code"
// xref). Mirrors a Python `{"value": ..., "methods": [...]}` row.
struct IocIndicator {
    std::string value;
    std::vector<std::string> methods;  // referencing method descriptors (may be empty)
};

// Network indicators bucketed by category, in dexllm.ioc.IOC_CATEGORIES order.
// Each list is sorted by value; the `methods` xref is populated highest-signal
// category first within an overall budget (mirrors extract_iocs's _XREF_PRIORITY).
struct IocResult {
    std::vector<IocIndicator> urls;
    std::vector<IocIndicator> ips;
    std::vector<IocIndicator> domains;
    std::vector<IocIndicator> emails;
    std::vector<IocIndicator> onion;
};

// Mirror of dexllm.ioc.extract_iocs. Scans ext.ListValueStrings() with the same
// refang + bounded regexes, validates bare domains against the bundled PSL, and
// (with_xref) attaches referencing methods via FindMethodsUsingStrings. `denoise`
// drops residual identifier hosts (dex package prefixes, xmlns authorities);
// `xref_limit` caps the number of cross-referenced indicators.
IocResult ExtractIocs(DexKitExt& ext, bool with_xref = true, bool denoise = true,
                      int xref_limit = 300);

// Test seam: run ONLY the scanners (refang + the five patterns + PSL validation +
// URL-host fold, denoise off, no xref) over a SUPPLIED string list — no DexKit
// needed. Lets a unit test inject crafted strings into a byte-identical
// differential against the Python scan (the corpus gate cannot inject strings).
// Returns each category's sorted values (IocIndicator.methods empty).
IocResult IocScanStrings(const std::vector<std::string>& strings);

// One content:// provider-URI hit: a bundled dataset URI referenced by the app,
// its provider `family`, and the referencing methods (xref).
struct ProviderHit {
    std::string uri;
    std::string family;
    std::vector<std::string> methods;
};

// Mirror of dexllm.providers.detect_content_providers (issue #13). A bundled
// content:// URI (gen/content_uris_data.h) is reported iff it occurs as a
// SUBSTRING of some value-string; `family` comes from the dataset and (with_xref)
// `methods` from the same L7 search the network IoCs use. Sorted by URI.
std::vector<ProviderHit> DetectContentProviders(DexKitExt& ext,
                                                bool with_xref = true,
                                                int xref_limit = 300);

// Test seam: the content:// substring match over a SUPPLIED string list (no xref).
// Returns (uri, family) hits sorted by URI, mirroring providers.match_content_uris.
std::vector<std::pair<std::string, std::string>> DetectProvidersFromStrings(
    const std::vector<std::string>& strings);

// ---------------------------------------------------------------------------
// Capability summarisation (issue #13, Phase 2) — C++ port of
// dexllm.capability.summarize_capabilities over the bundled API catalog
// (gen/android_api_data.h). Originally byte-faithful to c3ec1a1; re-synced to
// the semantics of dexllm v0.25.0's capability.py for dexllm-web#33:
// field-descriptor keys (dexllm#36), by_caller = API descriptors (dexllm#35),
// app_only (dexllm#49), shadowed sites excluded from counts (dexllm#107).

// One catalog API found in the APK. A catalog key is a METHOD descriptor
// (`Lcls;->name(proto)ret`) or a FIELD descriptor (`Lcls;->NAME:Ltype;`);
// a method key counts invoke instructions into call_site_count, a field key
// counts read instructions into the separate field_access_count (dexllm#36).
// Both count INSTRUCTIONS — the same unit — so summing them is meaningful;
// they stay apart so call_site_count's released meaning is untouched.
struct CapabilityApiHit {
    std::string api_signature;
    std::vector<std::string> permissions;  // catalog order (may be empty)
    std::vector<std::string> categories;   // catalog order, deduped
    std::vector<std::string> flags;        // orthogonal axis (e.g. IDENTIFIER)
    int call_site_count = 0;               // invoke instructions; 0 for a field key
    int field_access_count = 0;            // read instructions; 0 for a method key
    std::vector<std::string> callers;      // distinct toucher descriptors, sorted
};

// Aggregated capability profile. Counts are sorted maps (order-insensitive vs the
// Python Counter; deterministic for serialisation). api_hits is in catalog order.
// The three counter maps count TOUCHES: one per invoke instruction for a method
// entry, one per read instruction for a field entry.
struct CapabilityReport {
    std::map<std::string, int> permissions;  // permission -> #touches
    std::map<std::string, int> categories;   // category   -> #touches
    std::map<std::string, int> flags;        // flag       -> #touches
    // caller -> sorted API descriptors it touches (dexllm#35 — descriptors, not
    // permissions, so permission-less REFLECTION/CRYPTO/... entries register).
    std::map<std::string, std::vector<std::string>> by_caller;
    std::vector<CapabilityApiHit> api_hits;
    int total_call_sites = 0;      // invoke instructions, method entries only
    int total_field_accesses = 0;  // read instructions, field entries only
    std::string catalog_version;
    int catalog_size = 0;
    int matched_apis = 0;
    // What app_only REMOVED — 0 when it is false, so a filtered zero is
    // distinguishable from "this APK exercises none of the catalog" (dexllm#49).
    int dropped_touches = 0;  // same unit as total_call_sites + total_field_accesses
    int dropped_apis = 0;     // catalog entries that left api_hits entirely
    // Touches in a SHADOWED copy of their method (dexllm#107): the class resolves
    // to another loaded dex, so the copy never executes. Applied before app_only.
    int shadowed_touches = 0;
};

// Walk the bundled catalog, resolve each key by shape (method -> call sites,
// field -> read sites), aggregate permissions / categories / flags / by-caller.
// Mirrors v0.25.0 summarize_capabilities (without the only_categories filter).
// app_only (default true, like upstream) drops touches whose caller is bundled
// framework / official-library code. Deterministic (sorted maps + callers).
CapabilityReport SummarizeCapabilities(DexKitExt& ext, bool app_only = true);

}  // namespace dexkit::ext
