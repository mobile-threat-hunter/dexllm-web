// Node smoke for issue #13 WASM extractIocs(): asserts WasmDexKit.extractIocs()
// is byte-identical to the Python reference (dexllm.extract_iocs +
// detect_content_providers, reshaped by gen_ioc_reference.py to the same shape).
import { readFileSync } from "node:fs";
import createDexllm from "./build/dexllm.js";

const ref = JSON.parse(readFileSync("/tmp/ioc_ref.json", "utf8"));
const apks = Object.keys(ref);
const m = await createDexllm();
console.log("engine loaded;", apks.length, "reference APKs");

let failures = 0;
let netVals = 0;
let provVals = 0;
for (const apk of apks) {
  const buf = readFileSync(apk);
  try { m.FS.unlink("/input.bin"); } catch (_) {}
  m.FS.writeFile("/input.bin", new Uint8Array(buf));
  let dk;
  try { dk = new m.WasmDexKit("/input.bin"); }
  catch (e) { console.log("  LOAD FAIL", apk); failures++; continue; }

  const got = dk.extractIocs();
  dk.delete();
  const want = ref[apk];
  netVals += want.network.length;
  provVals += want.providers.length;

  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) {
    failures++;
    console.log("  MISMATCH", apk.split("/").pop());
    console.log("    want:", w.slice(0, 400));
    console.log("    got :", g.slice(0, 400));
  }
}

console.log(`checked ${apks.length} APKs; network rows=${netVals}, provider rows=${provVals}`);
if (failures) { console.error(failures, "mismatch(es)"); process.exit(1); }
console.log("ALL OK — WasmDexKit.extractIocs() == Python reference");
