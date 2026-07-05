#!/usr/bin/env python3
"""Dump the Python IoC reference in the WASM extractIocs() shape, for the node smoke.

For each bundled APK, computes dexllm.extract_iocs + detect_content_providers and
reshapes them exactly as the C++ embind `WasmDexKit::extractIocs` does — network as
a flat [{value, category, classes[]}] in IOC_CATEGORIES order, providers as
[{uri, family, classes[]}], where classes[] = the owner class of each xref method,
deduped preserving order. The smoke asserts dk.extractIocs() deep-equals this.
"""
import glob
import json
import sys
import warnings

warnings.filterwarnings("ignore")

import dexllm
from dexllm.ioc import IOC_CATEGORIES, extract_iocs
from dexllm.providers import detect_content_providers


def owner(desc):
    i = desc.find("->")
    return desc if i < 0 else desc[:i]


def classes_of(methods):
    seen = []
    for m in methods:
        c = owner(m)
        if c not in seen:
            seen.append(c)
    return seen


def reshape(dk):
    net = []
    iocs = extract_iocs(dk, with_xref=True, denoise=True, xref_limit=300)
    for cat in IOC_CATEGORIES:
        for row in iocs[cat]:
            net.append(
                {"value": row["value"], "category": cat,
                 "classes": classes_of(row["methods"])}
            )
    provs = [
        {"uri": p["uri"], "family": p["family"], "classes": classes_of(p["methods"])}
        for p in detect_content_providers(dk, with_xref=True, xref_limit=300)
    ]
    return {"network": net, "providers": provs}


def main():
    apks = sorted(glob.glob("/home/nyahumi/Project/dexllm/test_apk/APK/*.apk"))
    out = {}
    for apk in apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        out[apk] = reshape(dk)
    # ensure_ascii=False so non-ASCII values serialize as raw UTF-8, matching JS
    # JSON.stringify (Python's default would \u-escape them and diverge).
    json.dump(out, sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    main()
