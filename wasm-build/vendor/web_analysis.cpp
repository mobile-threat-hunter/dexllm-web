// web_analysis.cpp — SummarizeCapabilities, the capability engine port.
//
// VENDORED from dexllm native/core_ext/analysis.cpp at commit c3ec1a1 (removed
// from dexllm's core by 4b085d8; see vendor/include/web_analysis.h). The body is
// byte-faithful to c3ec1a1. PermissionCallers and the anonymous-namespace helpers
// stayed in dexllm's core analysis.cpp and are NOT duplicated here.

#include "web_analysis.h"

#include <map>
#include <set>
#include <string>
#include <utility>

#include "dexkit_ext.h"
#include "gen/android_api_data.h"

namespace dexkit::ext {

CapabilityReport SummarizeCapabilities(DexKitExt& ext) {
    CapabilityReport r;
    r.catalog_version = std::string(gen::kCapabilityCatalogVersion);
    r.catalog_size = static_cast<int>(gen::CapabilityCatalog().size());

    // caller -> set of permissions, built as sorted sets then flattened.
    std::map<std::string, std::set<std::string>> by_caller;
    for (const auto& e : gen::CapabilityCatalog()) {  // JSON/catalog order
        auto sites = ext.FindCallSitesToApi(e.api_signature);
        if (sites.empty()) continue;  // matches summarize_capabilities' `if not sites`

        CapabilityApiHit hit;
        hit.api_signature = e.api_signature;
        hit.permissions = e.permissions;
        hit.categories = e.categories;
        hit.call_site_count = static_cast<int>(sites.size());

        std::set<std::string> callers;
        for (const auto& s : sites) {
            ++r.total_call_sites;
            callers.insert(s.caller_descriptor);
            for (const auto& perm : e.permissions) {
                ++r.permissions[perm];
                by_caller[s.caller_descriptor].insert(perm);
            }
            for (const auto& cat : e.categories) ++r.categories[cat];
        }
        hit.callers.assign(callers.begin(), callers.end());  // sorted
        r.api_hits.push_back(std::move(hit));
    }
    for (auto& [caller, perms] : by_caller)
        r.by_caller[caller].assign(perms.begin(), perms.end());
    r.matched_apis = static_cast<int>(r.api_hits.size());
    return r;
}

}  // namespace dexkit::ext
