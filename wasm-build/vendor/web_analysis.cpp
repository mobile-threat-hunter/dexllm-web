// web_analysis.cpp — SummarizeCapabilities, the capability engine port.
//
// VENDORED from dexllm native/core_ext/analysis.cpp at commit c3ec1a1 (removed
// from dexllm's core by 4b085d8; see vendor/include/web_analysis.h), then
// RE-SYNCED to the semantics of dexllm v0.25.0's pure-Python capability.py for
// dexllm-web#33 — the deleted C++ copy never gained these:
//   - dexllm#36: a catalog key may be a FIELD descriptor (Lcls;->NAME:Ltype;),
//     dispatched on shape, resolved through the field-read xref and counted
//     into the separate field_access_count / total_field_accesses;
//   - dexllm#35: by_caller maps a caller to API DESCRIPTORS, not permissions
//     (nesting it in the permission loop lost every permission-less entry);
//   - dexllm#49: app_only (default true) drops framework/library callers,
//     reported via dropped_touches / dropped_apis;
//   - dexllm#107: a site in a shadowed copy of its method never executes, so
//     it is excluded from every count (shadowed_touches), before app_only.
// PermissionCallers and the core's anonymous-namespace helpers stayed in
// dexllm's analysis.cpp and are NOT duplicated here — except IsFrameworkCaller,
// which is anonymous there and therefore copied below.

#include "web_analysis.h"

#include <array>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dexkit_ext.h"
#include "gen/android_api_data.h"

namespace dexkit::ext {
namespace {

// Copy of core analysis.cpp's anonymous IsFrameworkCaller — the same prefix
// list as dexllm._callers._is_framework_caller, which capability.py shares
// with dangerous_permission_api_callers (same verb, same default).
constexpr std::array<std::string_view, 11> kFrameworkPrefixes = {{
    "Landroidx/", "Landroid/support/", "Landroid/arch/", "Lkotlin/",
    "Lkotlinx/", "Ljava/", "Ljavax/", "Ldalvik/", "Lcom/google/android/",
    "Lcom/google/common/", "Lcom/google/gson/",
}};
bool IsFrameworkCaller(const std::string& desc) {
    for (std::string_view p : kFrameworkPrefixes)
        if (std::string_view(desc).substr(0, p.size()) == p) return true;
    return false;
}

// The key's SHAPE selects the lookup: the member part of a field descriptor
// cannot contain '(' (a type descriptor is L…; / […  / one primitive letter),
// while a method's proto always opens with one (dexllm#36). Mirrors
// capability._is_field_key, including its str.partition behaviour on a key
// with no ";->" (empty member -> field-shaped; it routes to a lookup that
// answers nothing, which is what an unmatched entry does anyway).
bool IsFieldKey(const std::string& key) {
    auto pos = key.find(";->");
    if (pos == std::string::npos) return true;
    return key.find('(', pos + 3) == std::string::npos;
}

// Python's dict.fromkeys dedupe: drop repeats, keep first-occurrence order. A
// tag repeated inside one entry's list is malformed input, not a fact to count
// twice — counting it twice reproduces the inflation the two-axis split removed.
std::vector<std::string> DedupKeepOrder(const std::vector<std::string>& v) {
    std::vector<std::string> out;
    std::set<std::string> seen;
    for (const auto& s : v)
        if (seen.insert(s).second) out.push_back(s);
    return out;
}

}  // namespace

CapabilityReport SummarizeCapabilities(DexKitExt& ext, bool app_only) {
    CapabilityReport r;
    r.catalog_version = std::string(gen::kCapabilityCatalogVersion);
    r.catalog_size = static_cast<int>(gen::CapabilityCatalog().size());

    // caller -> set of API descriptors, built as sorted sets then flattened.
    std::map<std::string, std::set<std::string>> by_caller;
    for (const auto& e : gen::CapabilityCatalog()) {  // JSON/catalog order
        auto cats = DedupKeepOrder(e.categories);
        auto entry_flags = DedupKeepOrder(e.flags);

        const bool is_field = IsFieldKey(e.api_signature);
        // One list of TOUCHES whichever the key form, so every number below —
        // the Counters, by_caller, the per-hit counts and both totals — derives
        // from the same list and cannot disagree. A shadowed site never
        // executes under the session's load order (dexllm#107), so it is
        // dropped here, before app_only.
        std::vector<std::string> touches;
        if (is_field) {
            auto reads = ext.FindFieldReadSites(e.api_signature);
            for (const auto& s : reads)
                if (!s.shadowed) touches.push_back(s.method_descriptor);
            r.shadowed_touches += static_cast<int>(reads.size() - touches.size());
        } else {
            auto calls = ext.FindCallSitesToApi(e.api_signature);
            for (const auto& s : calls)
                if (!s.shadowed) touches.push_back(s.caller_descriptor);
            r.shadowed_touches += static_cast<int>(calls.size() - touches.size());
        }
        if (app_only) {
            std::vector<std::string> kept;
            for (const auto& c : touches)
                if (!IsFrameworkCaller(c)) kept.push_back(c);
            r.dropped_touches += static_cast<int>(touches.size() - kept.size());
            // `!touches.empty() &&` is load-bearing: the catalog is walked
            // WHOLE, so most entries arrive here already empty (the APK simply
            // does not use them) — counting those would make dropped_apis
            // report the catalog size minus the matches.
            if (!touches.empty() && kept.empty()) ++r.dropped_apis;
            touches = std::move(kept);
        }
        if (touches.empty()) continue;  // matches `if not touches`

        CapabilityApiHit hit;
        hit.api_signature = e.api_signature;
        hit.permissions = e.permissions;
        hit.categories = cats;
        hit.flags = entry_flags;
        hit.call_site_count = is_field ? 0 : static_cast<int>(touches.size());
        hit.field_access_count = is_field ? static_cast<int>(touches.size()) : 0;

        std::set<std::string> callers;
        for (const auto& caller : touches) {
            if (is_field) ++r.total_field_accesses;
            else ++r.total_call_sites;
            callers.insert(caller);
            // OUTSIDE the permission/tag loops (dexllm#35): an entry carrying
            // no permissions must still register its callers.
            by_caller[caller].insert(e.api_signature);
            for (const auto& perm : e.permissions) ++r.permissions[perm];
            for (const auto& cat : cats) ++r.categories[cat];
            for (const auto& fl : entry_flags) ++r.flags[fl];
        }
        hit.callers.assign(callers.begin(), callers.end());  // sorted
        r.api_hits.push_back(std::move(hit));
    }
    for (auto& [caller, apis] : by_caller)
        r.by_caller[caller].assign(apis.begin(), apis.end());
    r.matched_apis = static_cast<int>(r.api_hits.size());
    return r;
}

}  // namespace dexkit::ext
