"use strict";

const binaryReferenceWindowLimit = 64;
const binaryReferenceReportSchema = "pavarotti.binary-references.v1";
const binaryReferenceReportBytes = 4 * 1024 * 1024;

function binaryHexLocation(value) {
  return typeof value === "string" && /^0x(?:0|[1-9a-f][a-f0-9]{0,15})$/.test(value);
}

function binaryReferenceLocation(ref) {
  const anchor = ref.citation || ref.anchor;
  const location = {kind: anchor?.kind || "instruccion", index: anchor?.index ?? ref.index, row: anchor ? ref.index : 0,
    address: ref.instruction.address, offset: ref.instruction.offset};
  if (anchor?.path) location.path = anchor.path;
  const hash = ref.citation?.window_sha256 || ref.windowHash;
  if (hash) location.window_sha256 = hash;
  return location;
}

function binaryInstructionEntries(instructions, sections) {
  if (!Array.isArray(instructions)) return [];
  const entries = [];
  for (const [index, instruction] of instructions.entries()) {
    const section = Number.isInteger(instruction?.section) && sections[instruction.section];
    if (!section || !binaryHexLocation(instruction.address) || !binaryHexLocation(instruction.offset) || typeof instruction.bytes !== "string" ||
      typeof instruction.text !== "string" || (instruction.target !== undefined && !binaryHexLocation(instruction.target))) continue;
    entries.push({instruction, index, section, bytes: instruction.bytes.match(/.{1,2}/g)?.join(" ")});
  }
  return entries;
}

function binaryReferenceIndex(saved) {
  const windows = new Map();
  let restored;
  const byAddress = (image, address) => `${image}:${address}`;
  const sortLocation = (a, b) => a.length - b.length || a.localeCompare(b);
  const rank = (ref) => ref?.citation ? 3 : ref?.windowHash ? 2 : ref?.anchor ? 1 : 0;

  function group(entries, citation) {
    const locations = new Map();
    const targets = new Map();
    for (const {instruction, section, index, anchor, windowHash} of entries) {
      const image = section.image || 0;
      const address = byAddress(image, instruction.address);
      const offsets = locations.get(address) || new Set();
      offsets.add(instruction.offset);
      locations.set(address, offsets);
      if (!instruction.target || !instruction.text) continue;
      const target = byAddress(image, instruction.target);
      const refs = targets.get(target) || [];
      refs.push({instruction, image, index, citation: anchor ? undefined : citation, anchor, windowHash});
      targets.set(target, refs);
    }
    return {locations, targets};
  }

  const recorded = group(saved);
  function incoming(image, address, offset) {
    const target = byAddress(image, address);
    const refs = new Map();
    const sources = restored ? [recorded, restored, ...windows.values()] : [recorded, ...windows.values()];
    for (const source of sources) {
      const offsets = source.locations.get(target) || [];
      for (const location of offsets) {
        if (location !== offset) return {ambiguous: true, rows: []};
      }
      for (const ref of source.targets.get(target) || []) {
        const key = `${ref.instruction.address}:${ref.instruction.offset}`;
        if (rank(ref) >= rank(refs.get(key))) refs.set(key, ref);
      }
    }
    return {ambiguous: false, rows: Array.from(refs.values()).sort((a, b) =>
      sortLocation(a.instruction.address, b.instruction.address) || sortLocation(a.instruction.offset, b.instruction.offset))};
  }
  return {
    observe(citation, entries) {
      const key = `${citation.image}:${citation.address}:${citation.offset}`;
      windows.delete(key);
      windows.set(key, group(entries, citation));
      if (windows.size > binaryReferenceWindowLimit) windows.delete(windows.keys().next().value);
    },
    restore(report, instructions) {
      restored = group(report.origins.map((anchor, index) => ({instruction: instructions[index],
        section: {image: report.image}, index: anchor.row, anchor, windowHash: anchor.window_sha256})));
    },
    incoming,
    forSymbol(symbol) {
      const image = symbol.image ?? 0;
      if (!Number.isInteger(image) || image < 0 || symbol.forwarder || !binaryHexLocation(symbol.address) || !binaryHexLocation(symbol.offset)) {
        return {ambiguous: false, rows: []};
      }
      return incoming(image, symbol.address, symbol.offset);
    }
  };
}
