// Did the assistant act on the NEXT ROUND brief? The counter is lifted VERBATIM from ir-attested.ts and
// run over fanout rows of the shape a real sitting writes.
import fs from "fs";
const src = fs.readFileSync("inferroute_cli/pi_attested/ir-attested.ts", "utf8");
const a = src.indexOf("\tbriefFollowThrough() {");
const b = src.indexOf("\n\tsurfaces() {", a);
if (a < 0 || b < 0) { console.error("HARNESS: briefFollowThrough moved"); process.exit(2); }
const method = src.slice(a, b).replace(/^\tbriefFollowThrough\(\) \{/, "").replace(/\}\s*$/, "");
// The method is TypeScript, so it is written out and imported rather than built with `new Function`,
// which cannot strip types. Node's own type stripping runs it exactly as it ships.
import os from "os";
import path from "path";
const mod = path.join(os.tmpdir(), `brief_follow_${process.pid}.ts`);
fs.writeFileSync(mod, `export function follow(fanouts: Record<string, unknown>[]) {\n${
  method.replace(/this\.fanouts/g, "fanouts")}\n}\n`);
const { follow } = await import(`file://${mod}`);
const run = (fanouts) => follow(fanouts);

const out = {};
// Nothing asked, nothing owed.
out.noBriefs = run([{ generation: 1, brief_emitted: false }]);
// Asked and followed: a LATER press was the next generation.
out.followed = run([{ generation: 1, brief_emitted: true }, { generation: 2, brief_emitted: false }]);
// Asked and ignored — the signal this exists to catch.
out.ignored = run([{ generation: 1, brief_emitted: true }]);
// Asked, and another press happened that was NOT the next generation: a professional pressing the button
// again must not read as the assistant having obeyed.
out.anotherFirstPress = run([{ generation: 1, brief_emitted: true }, { generation: 1, brief_emitted: true }]);
// Two rounds, both asked, both followed.
out.twoRounds = run([{ generation: 1, brief_emitted: true }, { generation: 2, brief_emitted: true },
                     { generation: 3, brief_emitted: false }]);
// A press with no generation field at all (an older record) counts as the first.
out.legacy = run([{ brief_emitted: true }, { generation: 2 }]);
console.log(JSON.stringify(out));
