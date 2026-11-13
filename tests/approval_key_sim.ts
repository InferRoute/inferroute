// 13 Nov /search bench: on Intel TDX the verifier reports no `measurement`, the approval was keyed on "", nothing was
// stored, and every sealed search re-asked "This is the only time you will be asked". Runs the REAL approvalKey.
import fs from "fs";
import os from "os";
import path from "path";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("export function approvalKey(");
const b = src.indexOf("function searchProofOf(");
if (a < 0 || b < 0 || b < a) { console.error("HARNESS: approvalKey moved"); process.exit(2); }
const mod = path.join(os.tmpdir(), `approval_key_${process.pid}.ts`);
fs.writeFileSync(mod, src.slice(a, b));
const { approvalKey } = await import(`file://${mod}`);
fs.unlinkSync(mod);
let bad = 0; const fail = (m: string) => { console.error("FAIL: " + m); bad++; };
const img = "AB".repeat(48);
if (approvalKey({ measurement: "", image_sha384: img }) !== `tdx:${img.toLowerCase()}`) fail("TDX: key is tdx:+image sha384, lowercased");
if (approvalKey({ measurement: undefined, image_sha384: img }) !== `tdx:${img.toLowerCase()}`) fail("TDX with no measurement field");
if (approvalKey({ measurement: "snp-measure", image_sha384: img }) !== "snp-measure") fail("SNP measurement wins when present");
if (approvalKey({ measurement: "", image_sha384: "" }) !== "") fail("neither field: empty (never approved, asks again)");
if (approvalKey({ image_sha384: "not-hex" }) !== "") fail("a malformed image hash is not a key");
if (approvalKey(undefined) !== "") fail("no enclave: empty");
// The same verdict twice gives the same key, so a second search finds the first approval.
if (approvalKey({ image_sha384: img }) !== approvalKey({ image_sha384: img.toLowerCase() })) fail("stable across case");
if (!src.includes("const measurement = approvalKey(e);")) fail("ensureApproved must key on approvalKey");
if (bad) process.exit(1);
console.log("approval key: TDX approvals are held under tdx:+image, so one yes covers the matter");
