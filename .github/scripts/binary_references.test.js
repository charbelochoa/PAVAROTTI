const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../../ui/binary-references.js"), "utf8");
const {binaryInstructionEntries: entries, binaryReferenceIndex: indexReferences, binaryReferenceWindowLimit: limit} =
  vm.runInNewContext(`${source}\n({binaryInstructionEntries, binaryReferenceIndex, binaryReferenceWindowLimit})`);

const jump = (address, offset, target, section = 0) => ({address, offset, target, section, text: "jmp", bytes: "eb01"});
const target = (address, offset, section = 0) => ({address, offset, section, text: "ret", bytes: "c3"});

test("finds distinct origins and favors a verified copy of the same instruction", () => {
  const sections = [{image: 1}, {image: 2}];
  const saved = [jump("0x1000", "0x100", "0x1040"), target("0x1040", "0x140"),
    jump("0x1000", "0x300", "0x1040", 1), target("0x1040", "0x340", 1)];
  const index = indexReferences(entries(saved, sections));
  const citation = {image: 1, address: "0x1000", offset: "0x100", path: "0.0"};
  index.observe(citation, entries([saved[0], jump("0x1020", "0x120", "0x1040")], sections));
  const refs = index.incoming(1, "0x1040", "0x140").rows;
  assert.equal(refs.length, 2);
  assert.equal(refs[0].instruction.offset, "0x100");
  assert.equal(refs[0].citation, citation);
  assert.equal(refs[1].instruction.offset, "0x120");
  assert.equal(refs[1].index, 1);
  const otherImage = index.incoming(2, "0x1040", "0x340").rows;
  assert.equal(otherImage.length, 1);
  assert.equal(otherImage[0].instruction.offset, "0x300");
  assert.equal(otherImage[0].citation, undefined);
});

test("reports conflicting physical offsets for the same address in an image", () => {
  const sections = [{image: 1}];
  const index = indexReferences(entries([jump("0x1000", "0x100", "0x1040"), target("0x1040", "0x140")], sections));
  index.observe({image: 1, address: "0x1040", offset: "0x240"}, entries([target("0x1040", "0x240")], sections));
  for (const offset of ["0x140", "0x240"]) {
    const result = index.incoming(1, "0x1040", offset);
    assert.equal(result.ambiguous, true);
    assert.equal(result.rows.length, 0);
  }
});

test("keeps the verified origin of a replayed jump before the parent window opens", () => {
  const sections = [{image: 1}];
  const index = indexReferences([]);
  const original = entries([jump("0x1000", "0x300", "0x1100")], sections)[0];
  const destination = entries([target("0x1100", "0x400")], sections)[0];
  const anchor = {kind: "entrada", index: 1, path: ""};
  const child = {image: 1, address: "0x1100", offset: "0x400", path: "0"};
  const observation = [destination, {...original, anchor}];
  index.observe(child, observation);
  const replayed = index.incoming(1, "0x1100", "0x400").rows;
  assert.equal(replayed.length, 1);
  assert.equal(replayed[0].anchor, anchor);
  assert.equal(replayed[0].citation, undefined);
  const parent = {image: 1, address: "0x1000", offset: "0x300"};
  index.observe(parent, [original]);
  index.observe(child, observation);
  const reopened = index.incoming(1, "0x1100", "0x400").rows;
  assert.equal(reopened.length, 1);
  assert.equal(reopened[0].citation, parent);
});

test("retains saved references and evicts the oldest of the observed windows", () => {
  const sections = [{}];
  const location = "0xf000";
  const index = indexReferences(entries([jump("0x100", "0x200", location)], sections));
  for (let i = 0; i <= limit; i++) {
    const address = `0x${(0x1000 + i).toString(16)}`;
    index.observe({image: 0, address, offset: address}, entries([jump(address, address, location)], sections));
  }
  const result = index.incoming(0, location, "0xf00");
  assert.equal(result.rows.length, limit + 1);
  assert.equal(result.rows[0].instruction.offset, "0x200");
  assert.equal(result.rows.some((row) => row.instruction.offset === "0x1000"), false);
  assert.equal(result.rows[1].instruction.offset, "0x1001");
});
