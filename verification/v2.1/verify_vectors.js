// Cross-language check of canonicalization-vectors.json.
//   node verify_vectors.js
// Uses JSON.stringify for strings and numbers, which already matches RFC 8785 in JS,
// and sorts members by UTF-16 code unit, which is what Array.prototype.sort does.
const fs = require("fs"), crypto = require("crypto");
function jcs(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
}
const doc = JSON.parse(fs.readFileSync(__dirname + "/canonicalization-vectors.json", "utf8"));
let bad = 0;
for (const v of doc.vectors) {
  const s = jcs(v.value);
  const h = "sha256:" + crypto.createHash("sha256").update(s, "utf8").digest("hex");
  const ok = s === v.jcs && h === v.sha256;
  if (!ok) { bad++; console.log(`FAIL ${v.name}\n  js  ${s}\n  py  ${v.jcs}`); }
  else console.log(`PASS ${v.name}  ${s}`);
}
console.log(`\n${doc.vectors.length} vectors, ${bad} failed`);
process.exit(bad ? 1 : 0);
