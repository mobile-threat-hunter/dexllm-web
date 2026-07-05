// Node smoke for issue #13 WASM extractIocs(): asserts WasmDexKit.extractIocs()
// is byte-identical to the Python reference (dexllm.extract_iocs +
// detect_content_providers, reshaped by gen_ioc_reference.py to the same shape).
import { readFileSync } from "node:fs";
import createDexllm from "./build/dexllm.js";

const ref = JSON.parse(readFileSync("/tmp/ioc_ref.json", "utf8"));
const apks = Object.keys(ref);
const m = await createDexllm();
console.log("engine loaded;", apks.length, "reference APKs");

// Canonical JSON: sort object keys recursively (arrays keep order). Lets us compare
// the WASM output (std::map = sorted keys, camelCase) to the Python reference
// (Counter = insertion order) as pure data — object key order is irrelevant.
function canon(x) {
  if (Array.isArray(x)) return x.map(canon);
  if (x && typeof x === "object") {
    const o = {};
    for (const k of Object.keys(x).sort()) o[k] = canon(x[k]);
    return o;
  }
  return x;
}
const ceq = (a, b) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));

let failures = 0;
let netVals = 0;
let provVals = 0;
let capMatched = 0;
for (const apk of apks) {
  const buf = readFileSync(apk);
  try { m.FS.unlink("/input.bin"); } catch (_) {}
  m.FS.writeFile("/input.bin", new Uint8Array(buf));
  let dk;
  try { dk = new m.WasmDexKit("/input.bin"); }
  catch (e) { console.log("  LOAD FAIL", apk); failures++; continue; }

  const got = dk.extractIocs();
  const gotCaps = dk.summarizeCapabilities();
  dk.delete();
  const want = ref[apk];
  netVals += want.network.length;
  provVals += want.providers.length;
  if (want.capabilities.matchedApis > 0) capMatched++;

  // extractIocs: fixed key order both sides -> exact stringify is fine.
  if (JSON.stringify(got) !== JSON.stringify({ network: want.network, providers: want.providers })) {
    failures++;
    console.log("  IOC MISMATCH", apk.split("/").pop());
    console.log("    got :", JSON.stringify(got).slice(0, 400));
  }
  // summarizeCapabilities: canonical compare (sorted-map vs Counter key order).
  if (!ceq(gotCaps, want.capabilities)) {
    failures++;
    console.log("  CAPABILITY MISMATCH", apk.split("/").pop());
    console.log("    want:", JSON.stringify(canon(want.capabilities)).slice(0, 500));
    console.log("    got :", JSON.stringify(canon(gotCaps)).slice(0, 500));
  }
}

console.log(`checked ${apks.length} APKs; network=${netVals}, providers=${provVals}, capability-matched APKs=${capMatched}`);
if (failures) { console.error(failures, "mismatch(es)"); process.exit(1); }
console.log("ALL OK — WasmDexKit.extractIocs() + summarizeCapabilities() == Python reference");
