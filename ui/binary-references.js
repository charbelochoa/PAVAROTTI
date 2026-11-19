"use strict";

const binaryReferenceWindowLimit = 64;

function binaryInstructionEntries(instructions, sections) {
  if (!Array.isArray(instructions)) return [];
  const hex = (value) => typeof value === "string" && /^0x(?:0|[1-9a-f][a-f0-9]{0,15})$/.test(value);
  const entries = [];
  for (const [index, instruction] of instructions.entries()) {
    const section = Number.isInteger(instruction?.section) && sections[instruction.section];
    if (!section || !hex(instruction.address) || !hex(instruction.offset) || typeof instruction.bytes !== "string" ||
      typeof instruction.text !== "string" || (instruction.target !== undefined && !hex(instruction.target))) continue;
    entries.push({instruction, index, section, bytes: instruction.bytes.match(/.{1,2}/g)?.join(" ")});
  }
  return entries;
}

function binaryReferenceIndex(saved) {
  const windows = new Map();
  const byAddress = (image, address) => `${image}:${address}`;
  const sortLocation = (a, b) => a.length - b.length || a.localeCompare(b);

  function group(entries, citation) {
    const locations = new Map();
    const targets = new Map();
    for (const {instruction, section, index, anchor} of entries) {
      const image = section.image || 0;
      const address = byAddress(image, instruction.address);
      const offsets = locations.get(address) || new Set();
      offsets.add(instruction.offset);
      locations.set(address, offsets);
      if (!instruction.target || !instruction.text) continue;
      const target = byAddress(image, instruction.target);
      const refs = targets.get(target) || [];
      refs.push({instruction, image, index, citation: anchor ? undefined : citation, anchor});
      targets.set(target, refs);
    }
    return {locations, targets};
  }

  const recorded = group(saved);
  return {
    observe(citation, entries) {
      const key = `${citation.image}:${citation.address}:${citation.offset}`;
      windows.delete(key);
      windows.set(key, group(entries, citation));
      if (windows.size > binaryReferenceWindowLimit) windows.delete(windows.keys().next().value);
    },
    incoming(image, address, offset) {
      const target = byAddress(image, address);
      const refs = new Map();
      for (const source of [recorded, ...windows.values()]) {
        const offsets = source.locations.get(target) || [];
        for (const location of offsets) {
          if (location !== offset) return {ambiguous: true, rows: []};
        }
        for (const ref of source.targets.get(target) || []) {
          const key = `${ref.instruction.address}:${ref.instruction.offset}`;
          if (!refs.get(key)?.citation || ref.citation) refs.set(key, ref);
        }
      }
      return {ambiguous: false, rows: Array.from(refs.values()).sort((a, b) =>
        sortLocation(a.instruction.address, b.instruction.address) || sortLocation(a.instruction.offset, b.instruction.offset))};
    }
  };
}
