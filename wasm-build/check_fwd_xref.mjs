// Cross-check findCallSitesFromMethod (engine, bytecode) against the UI's
// current approach (regex over renderMethodSmali). Same invoke set expected.
import { readFileSync } from "node:fs";
import createDexllm from "./build/dexllm.js";

const APK = process.argv[2] || "/home/nyahumi/Project/dexllm/test_apk/APK/a2dp.Vol_137.apk";

// Mirror of index.html:2722 smaliInvokesFrom's regex.
const RE = /^\s*(?:0x[0-9a-f]+\s*:\s*)?invoke-([a-z\/-]+)\s*\{([^}]*)\}\s*,\s*(L[\w\/$]+;->[^\s(]+\([^)]*\)[^\s]+)/i;

const m = await createDexllm();
const buf = readFileSync(APK);
m.FS.writeFile("/input.bin", new Uint8Array(buf));
const dk = new m.WasmDexKit("/input.bin");

const classes = dk.listClasses();
let checked = 0, agree = 0, mismatch = 0, engineEmpty = 0, withOffset = 0;
const samples = [];

outer:
for (let c = 0; c < classes.size(); c++) {
  const cls = classes.get(c);
  let methods;
  try { methods = dk.listClassMethods(cls); } catch (_) { continue; }
  for (let i = 0; i < methods.size(); i++) {
    const md = methods.get(i);
    let smali;
    try { smali = dk.renderMethodSmali(md); } catch (_) { continue; }
    const fromSmali = [];
    for (const line of smali.split("\n")) {
      const g = line.match(RE);
      if (g) fromSmali.push(g[3]);
    }
    if (!fromSmali.length) continue;

    const fwd = dk.findCallSitesFromMethod(md);
    const fromEngine = [];
    for (let j = 0; j < fwd.length; j++) {
      fromEngine.push(fwd[j].callee);
      if (fwd[j].offset >= 0) withOffset++;
    }

    checked++;
    if (!fromEngine.length) { engineEmpty++; continue; }

    const a = [...fromSmali].sort().join("\n");
    const b = [...fromEngine].sort().join("\n");
    if (a === b) agree++;
    else {
      mismatch++;
      if (samples.length < 5) {
        const sa = new Set(fromSmali), sb = new Set(fromEngine);
        samples.push({
          method: md,
          onlySmali: [...sa].filter(x => !sb.has(x)).slice(0, 4),
          onlyEngine: [...sb].filter(x => !sa.has(x)).slice(0, 4),
        });
      }
    }
    if (checked >= 400) break outer;
  }
  methods.delete();
}
classes.delete();

console.log(`methods with invokes checked : ${checked}`);
console.log(`  identical invoke set       : ${agree}`);
console.log(`  engine returned empty      : ${engineEmpty}`);
console.log(`  mismatched                 : ${mismatch}`);
console.log(`  invokes carrying an offset  : ${withOffset}`);
for (const s of samples) {
  console.log(`\n  MISMATCH ${s.method}`);
  if (s.onlySmali.length)  console.log(`    smali-only : ${s.onlySmali.join(", ")}`);
  if (s.onlyEngine.length) console.log(`    engine-only: ${s.onlyEngine.join(", ")}`);
}
dk.delete();
