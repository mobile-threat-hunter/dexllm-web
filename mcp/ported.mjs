// Logic ported from ../index.html (single-file constraint prevents sharing the
// code directly, so each block cites its source lines; keep in sync manually).
// Engine calls (permissionCallers / summarizeCapabilities / findClassesBy-
// Superclass) stay in the engine — only the JS-side shaping lives here.

// ── index.html:1374,1376 ─────────────────────────────────────────────────────
export const descToJava = d =>
  (d.startsWith("L") && d.endsWith(";")) ? d.slice(1, -1).replace(/\//g, ".") : d;
export const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ── rename store (index.html:1388-1402, session-local — no localStorage) ─────
export const renameStore = { classes: new Map(), methods: new Map(), fields: new Map() };
let _dottedDisplayToDesc = new Map();

export const renameCount = () =>
  renameStore.classes.size + renameStore.methods.size + renameStore.fields.size;

export function setRenames(obj) {
  renameStore.classes = new Map(Object.entries(obj?.classes || {}));
  renameStore.methods = new Map(Object.entries(obj?.methods || {}));
  renameStore.fields  = new Map(Object.entries(obj?.fields  || {}));
  rebuildRenameMaps();
}
export function clearRenames() { setRenames(null); }

// index.html:1485-1494 (simple-name reverse map omitted — unused server-side)
function rebuildRenameMaps() {
  _dottedDisplayToDesc = new Map();
  for (const desc of renameStore.classes.keys()) {
    _dottedDisplayToDesc.set(displayDotted(desc), desc);
  }
}

// ── display helpers (index.html:1406-1483) ───────────────────────────────────
export function displayClassDesc(desc) {
  if (!renameStore.classes.size || !desc.startsWith("L") || !desc.endsWith(";")) return desc;
  const body = desc.slice(1, -1);
  const slash = body.lastIndexOf("/");
  const prefix = body.slice(0, slash + 1);
  let acc = "";
  const segs = body.slice(slash + 1).split("$").map(s => {
    acc = acc ? acc + "$" + s : s;
    return renameStore.classes.get("L" + prefix + acc + ";") || s;
  });
  return "L" + prefix + segs.join("$") + ";";
}
export function displayDotted(desc) { return descToJava(displayClassDesc(desc)); }
export function displayBare(desc) {
  const b = displayClassDesc(desc).slice(1, -1);
  return b.slice(b.lastIndexOf("/") + 1);
}
export function displayMember(cls, kind, name) {
  const m = kind === "f" ? renameStore.fields : renameStore.methods;
  return m.get(cls + "->" + name) || name;
}
// index.html:1445-1454
export function origDottedToDesc(dotted) {
  const hit = _dottedDisplayToDesc.get(dotted);
  if (hit) return hit;
  let i = dotted.length;
  while ((i = dotted.lastIndexOf("$", i - 1)) > 0) {
    const pre = _dottedDisplayToDesc.get(dotted.slice(0, i));
    if (pre) return pre.slice(0, -1) + dotted.slice(i) + ";";
  }
  return null;
}
// index.html:1460-1483
export function displayDesc(desc) {
  if (!renameCount()) return desc;
  const a = desc.indexOf("->");
  if (a < 0) return displayClassDesc(desc);
  const cls = desc.slice(0, a);
  let rest = desc.slice(a + 2);
  const p = rest.indexOf("("), c = rest.indexOf(":");
  if (p >= 0 && (c < 0 || p < c)) {
    rest = displayMember(cls, "m", rest.slice(0, p)) + renameDescTypes(rest.slice(p));
  } else if (c >= 0) {
    rest = displayMember(cls, "f", rest.slice(0, c)) + renameDescTypes(rest.slice(c));
  } else {
    rest = displayMember(cls, "m", rest);
  }
  return displayClassDesc(cls) + "->" + rest;
}
function renameDescTypes(s) {
  for (const desc of renameStore.classes.keys()) {
    if (!s.includes(desc)) continue;
    s = s.split(desc).join(displayClassDesc(desc));
  }
  return s;
}

// ── applyRenames (index.html:1535-1613) ──────────────────────────────────────
// Tier order and string-literal preservation are invariants shared with the
// web viewer; see the source block comment there for the full rationale.
const _STR_SEG_RE = /"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g;
export function applyRenames(text, cls) {
  if (!renameCount()) return text;
  const subs = [];
  const push = (re, map) => subs.push([re, (m, g) => map.get(g)]);

  const ownDotted = descToJava(cls);
  const mMap = new Map(), fMap = new Map();
  for (const [k, v] of renameStore.methods) {
    if (k.startsWith(cls + "->")) mMap.set(k.slice(cls.length + 2), v);
  }
  for (const [k, v] of renameStore.fields) {
    if (k.startsWith(cls + "->")) fMap.set(k.slice(cls.length + 2), v);
  }
  if (mMap.size) {
    const alt = "(" + [...mMap.keys()].map(escRe).join("|") + ")";
    push(new RegExp("(?<![\\w$.@])" + alt + "(?=\\s*\\()", "g"), mMap);
    push(new RegExp("(?<=(?:this|" + escRe(ownDotted) + ")\\.)" + alt + "(?=\\s*\\()", "g"), mMap);
  }
  if (fMap.size) {
    const alt = "(" + [...fMap.keys()].map(escRe).join("|") + ")";
    push(new RegExp("(?<![\\w$.@])" + alt + "(?![\\w$.]|\\s*\\()", "g"), fMap);
    push(new RegExp("(?<=(?:this|" + escRe(ownDotted) + ")\\.)" + alt + "(?![\\w$(])", "g"), fMap);
  }

  const cMap = new Map();
  for (const desc of renameStore.classes.keys()) {
    const from = descToJava(desc), to = displayDotted(desc);
    if (from !== to) cMap.set(from, to);
  }
  if (cMap.size) {
    const alt = "(" + [...cMap.keys()].sort((a, b) => b.length - a.length).map(escRe).join("|") + ")";
    push(new RegExp("(?<![\\w$.])" + alt + "(?![\\w$])", "g"), cMap);   // C1 exact
    push(new RegExp("(?<![\\w$.])" + alt + "(?=\\$)", "g"), cMap);      // C2 inner propagation
  }
  {
    const bare = cls.slice(1, -1).slice(cls.slice(1, -1).lastIndexOf("/") + 1);
    const bareTo = displayBare(cls);
    if (bare !== bareTo) {
      const map = new Map([[bare, bareTo]]);
      push(new RegExp("(?<![\\w$.])(" + escRe(bare) + ")(?![\\w$.])", "g"), map);
    }
  }
  if (!subs.length) return text;

  const run = (seg) => {
    for (const [re, fn] of subs) seg = seg.replace(re, fn);
    return seg;
  };
  const out = [];
  let last = 0, m;
  _STR_SEG_RE.lastIndex = 0;
  while ((m = _STR_SEG_RE.exec(text))) {
    out.push(run(text.slice(last, m.index)), m[0]);
    last = _STR_SEG_RE.lastIndex;
  }
  out.push(run(text.slice(last)));
  return out.join("");
}

// ── permission bucketing + flattening (index.html:1082-1086, 1727-1744) ─────
export const levelBucket = lvl =>
  lvl === "dangerous" ? "dangerous" :
  (lvl === "signature" || lvl === "signatureOrSystem") ? "signature" :
  lvl === "internal" ? "internal" :
  lvl === "normal" ? "normal" : "other";

export function computePerms(dkInst, appOnly = true) {
  const permIndex = [];
  const perms = new Set(), callersAll = new Set();
  for (const g of dkInst.permissionCallers(appOnly)) {
    const level = levelBucket(g.protectionLevel || "unknown");
    for (const row of g.rows) {
      if (!row.callers.length) continue;
      permIndex.push({ perm: g.perm, level, api: row.api, callers: row.callers });
      perms.add(g.perm); for (const c of row.callers) callersAll.add(c);
    }
  }
  return {
    permIndex,
    totals: { perms: perms.size, apis: permIndex.length, callers: callersAll.size },
  };
}

// ── component candidates (index.html:1113-1124, 1753-1780) ──────────────────
// Ordered MOST SPECIFIC FIRST; first match wins (DeviceAdminReceiver would
// otherwise drown in the plain receiver bucket). dex-only: these are
// candidates by superclass chain, NOT manifest-declared components.
export const COMPONENT_BASES = [
  { base: "Landroid/app/admin/DeviceAdminReceiver;",                    kind: "device-admin",   tag: "DA" },
  { base: "Landroid/accessibilityservice/AccessibilityService;",        kind: "accessibility",  tag: "AX" },
  { base: "Landroid/service/notification/NotificationListenerService;", kind: "notif-listener", tag: "NL" },
  { base: "Landroid/net/VpnService;",                                   kind: "vpn",            tag: "VPN" },
  { base: "Landroid/app/job/JobService;",                               kind: "job",            tag: "J" },
  { base: "Landroid/app/Application;",                                  kind: "application",    tag: "APP" },
  { base: "Landroid/content/ContentProvider;",                          kind: "provider",       tag: "P" },
  { base: "Landroid/content/BroadcastReceiver;",                        kind: "receiver",       tag: "R" },
  { base: "Landroid/app/Service;",                                      kind: "service",        tag: "S" },
  { base: "Landroid/app/Activity;",                                     kind: "activity",       tag: "A" },
];

// BFS to the transitive closure — findClassesBySuperclass is direct-only.
export function computeComponents(dkInst) {
  const componentIndex = new Map();
  const groups = [];
  for (const entry of COMPONENT_BASES) {
    const found = [];
    const seen = new Set([entry.base]);
    let frontier = [entry.base];
    while (frontier.length) {
      const next = [];
      for (const cls of frontier) {
        let subs;
        try { subs = dkInst.findClassesBySuperclass(cls); } catch (_) { continue; }
        for (let i = 0; i < subs.size(); i++) {
          const s = subs.get(i);
          if (seen.has(s)) continue;
          seen.add(s); next.push(s);
          if (!componentIndex.has(s)) { componentIndex.set(s, entry); found.push(s); }
        }
        subs.delete();
      }
      frontier = next;
    }
    if (found.length) groups.push({ kind: entry.kind, tag: entry.tag, classes: found.sort() });
  }
  return groups;
}

// ── capability profile normalization (index.html:1852-1884) ──────────────────
// Plain-JS up front: apiHits is an embind vector of embind objects.
export function computeCaps(dkInst, appOnly = true) {
  const r = dkInst.summarizeCapabilities(appOnly);
  return {
    categories: { ...r.categories },
    permissions: { ...r.permissions },
    flags: { ...r.flags },
    catalogVersion: r.catalogVersion,
    catalogSize: r.catalogSize,
    matchedApis: r.matchedApis,
    totalCallSites: r.totalCallSites,
    totalFieldAccesses: r.totalFieldAccesses,
    droppedTouches: r.droppedTouches,
    droppedApis: r.droppedApis,
    shadowedTouches: r.shadowedTouches,
    apiHits: Array.from(r.apiHits, h => ({
      apiSignature: h.apiSignature,
      permissions: Array.from(h.permissions),
      categories: Array.from(h.categories),
      flags: Array.from(h.flags),
      callSiteCount: h.callSiteCount,
      fieldAccessCount: h.fieldAccessCount,
      callers: Array.from(h.callers),
    })),
  };
}
