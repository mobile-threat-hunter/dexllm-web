// Node smoke test for the new dexllm.wasm. Verifies the single-threaded
// build can load bare .dex, multidex .apk, and a couple of other forms,
// and that the API the dexllm-web index.html actually uses still works.
import { readFileSync } from "node:fs";
import { argv } from "node:process";
import createDexllm from "./build/dexllm.js";

const TESTS = [
  ["bare .dex",          "/home/nyahumi/Project/dexllm/test_apk/APK/classes.dex"],
  ["app-prod-debug apk", "/home/nyahumi/Project/dexllm/test_apk/APK/app-prod-debug.apk"],
  ["multidex apk",       "/home/nyahumi/Project/dexllm/test_apk/APK/multidex.apk"],
  ["a2dp.Vol_137 apk",   "/home/nyahumi/Project/dexllm/test_apk/APK/a2dp.Vol_137.apk"],
];

const m = await createDexllm();
console.log("engine loaded");

let failures = 0;
for (const [label, path] of TESTS) {
  console.log("---", label, path);
  const buf = readFileSync(path);
  try { m.FS.unlink("/input.bin"); } catch (_) {}
  m.FS.writeFile("/input.bin", new Uint8Array(buf));
  let dk;
  try { dk = new m.WasmDexKit("/input.bin"); }
  catch (e) {
    const msg = (typeof e === "number" && m.getExceptionMessage) ? m.getExceptionMessage(e) : e;
    console.log("  LOAD FAILED:", msg); failures++; continue;
  }
  console.log("  dexCount=", dk.dexCount());
  const rep = dk.verifyReport();
  console.log("  verifyReport length=", rep.length, "  first=", JSON.stringify(rep[0] ?? null));
  const vec = dk.listClasses();
  const nClasses = vec.size();
  const firstClass = nClasses ? vec.get(0) : null;
  vec.delete();
  console.log("  classes=", nClasses, "  first=", firstClass);
  // decompile something small so we exercise the DAD pipeline
  if (firstClass) {
    const java = dk.decompileClassJava(firstClass);
    console.log("  decompiled first class:", java.length, "chars");
  }
  const sv = dk.listValueStrings();
  console.log("  strings=", sv.size());
  sv.delete();
  const tv = dk.listExternalTypeRefs();
  console.log("  externalTypeRefs=", tv.size());
  tv.delete();
  dk.delete();
}

if (failures) { console.error(failures, "test(s) failed"); process.exit(1); }
console.log("ALL OK");
