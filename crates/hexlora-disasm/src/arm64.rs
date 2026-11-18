//! AArch64 decoding through `yaxpeax-arm`.

use crate::{Decoded, ExtentTracker, FlowKind, Instruction, Program};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction as Raw, Opcode, Operand};

fn flow_of(opcode: Opcode) -> FlowKind {
    match opcode {
        Opcode::BL
        | Opcode::BLR
        | Opcode::BLRAA
        | Opcode::BLRAAZ
        | Opcode::BLRAB
        | Opcode::BLRABZ => FlowKind::Call,
        Opcode::B | Opcode::BR => FlowKind::Jump,
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
            FlowKind::ConditionalJump
        }
        Opcode::RET | Opcode::RETAA | Opcode::RETAB => FlowKind::Return,
        Opcode::BRK | Opcode::UDF => FlowKind::Trap,
        Opcode::Invalid => FlowKind::Invalid,
        _ => FlowKind::Next,
    }
}

fn pc_offset(raw: &Raw) -> Option<i64> {
    raw.operands.iter().find_map(|operand| match operand {
        Operand::PCOffset(offset) => Some(*offset),
        _ => None,
    })
}

fn register(operand: &Operand) -> Option<u16> {
    match operand {
        Operand::Register(_, number) | Operand::RegisterOrSP(_, number) => Some(*number),
        _ => None,
    }
}

fn immediate(operand: &Operand) -> Option<u64> {
    match operand {
        Operand::Immediate(value) => Some(*value as u64),
        Operand::Imm64(value) => Some(*value),
        Operand::Imm16(value) => Some(*value as u64),
        Operand::ImmShift(value, shift) => Some((*value as u64) << shift),
        _ => None,
    }
}

/// The page addresses `adrp` has put in registers, so a following `add` or
/// `ldr` can be resolved to the address it forms.
#[derive(Default)]
struct Pages([Option<u64>; 32]);

impl Pages {
    fn set(&mut self, register: u16, value: Option<u64>) {
        if let Some(slot) = self.0.get_mut(register as usize) {
            *slot = value;
        }
    }
    fn get(&self, register: u16) -> Option<u64> {
        self.0.get(register as usize).copied().flatten()
    }
    /// A call may change any register the callee is allowed to clobber.
    fn clear(&mut self) {
        self.0 = [None; 32];
    }
}

/// What address, if any, an instruction forms from a tracked page, and whether
/// it reads through it (`ldr`) or just computes it (`add`, `adr`).
enum Formed {
    Address(u64),
    Load(u64),
}

fn track(pages: &mut Pages, raw: &Raw, address: u64) -> Option<Formed> {
    match raw.opcode {
        Opcode::ADRP => {
            let destination = register(&raw.operands[0])?;
            let page = (address & !0xfff).wrapping_add(pc_offset(raw)? as u64);
            pages.set(destination, Some(page));
            None
        }
        Opcode::ADR => {
            let destination = register(&raw.operands[0])?;
            let formed = address.wrapping_add(pc_offset(raw)? as u64);
            pages.set(destination, Some(formed));
            Some(Formed::Address(formed))
        }
        Opcode::ADD => {
            let destination = register(&raw.operands[0])?;
            let formed = register(&raw.operands[1])
                .and_then(|source| pages.get(source))
                .zip(immediate(&raw.operands[2]))
                .map(|(page, offset)| page.wrapping_add(offset));
            pages.set(destination, formed);
            formed.map(Formed::Address)
        }
        Opcode::LDR | Opcode::LDRSW => {
            let destination = register(&raw.operands[0]);
            let formed = match &raw.operands[1] {
                // A literal load reads straight from a PC-relative address.
                Operand::PCOffset(offset) => Some(address.wrapping_add(*offset as u64)),
                Operand::RegPreIndex(base, offset, false) => pages
                    .get(*base)
                    .map(|page| page.wrapping_add(*offset as i64 as u64)),
                _ => None,
            };
            if let Some(destination) = destination {
                pages.set(destination, None);
            }
            formed.map(Formed::Load)
        }
        _ => {
            // Any other write to a register invalidates what was tracked.
            if let Some(destination) = register(&raw.operands[0]) {
                pages.set(destination, None);
            }
            None
        }
    }
}

fn decode_one(window: &[u8]) -> Option<Raw> {
    let chunk = window.get(..4)?;
    InstDecoder::default()
        .decode(&mut U8Reader::new(chunk))
        .ok()
        .filter(|raw| raw.opcode != Opcode::Invalid)
}

/// If `address` holds a stub that loads an import slot and branches to it,
/// returns the import's name. Covers Mach-O stubs and ELF PLT entries.
pub(crate) fn stub_target<'p>(program: &'p Program, bytes: &[u8], address: u64) -> Option<&'p str> {
    if !program.is_code(address) {
        return None;
    }
    let window = program.bytes_at(bytes, address, 16)?;
    let mut pages = Pages::default();
    let mut slot = None;
    for (index, chunk) in window.chunks_exact(4).enumerate() {
        let raw = decode_one(chunk)?;
        let at = address + index as u64 * 4;
        match flow_of(raw.opcode) {
            FlowKind::Next => {
                if let Some(Formed::Load(loaded)) = track(&mut pages, &raw, at) {
                    slot = Some(loaded);
                }
            }
            FlowKind::Jump if raw.opcode == Opcode::BR => {
                return slot.and_then(|slot| program.import_at(slot));
            }
            _ => return None,
        }
    }
    None
}

pub(crate) fn decode(
    program: &Program,
    bytes: &[u8],
    window: &[u8],
    start: u64,
    max: usize,
    infer_end: bool,
) -> (Vec<Instruction>, Decoded) {
    let window_end = start + window.len() as u64;
    let mut pages = Pages::default();
    let mut extent = ExtentTracker::default();
    let mut instructions = Vec::new();
    for (index, chunk) in window.chunks_exact(4).enumerate() {
        if instructions.len() >= max {
            return (instructions, Decoded::Limit);
        }
        let address = start + index as u64 * 4;
        let Some(raw) = decode_one(chunk) else {
            instructions.push(Instruction {
                address,
                bytes: chunk.to_vec(),
                text: format!(
                    ".word 0x{:08x}",
                    u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                ),
                flow: FlowKind::Invalid,
                target: None,
                comment: None,
            });
            continue;
        };
        let flow = flow_of(raw.opcode);
        let is_branch = matches!(
            flow,
            FlowKind::Call | FlowKind::Jump | FlowKind::ConditionalJump
        );
        let target = is_branch
            .then(|| pc_offset(&raw))
            .flatten()
            .map(|offset| address.wrapping_add(offset as u64));
        let formed = if is_branch {
            None
        } else {
            track(&mut pages, &raw, address)
        };
        let comment = if let Some(target) = target {
            let internal =
                flow != FlowKind::Call && target >= start && target < window_end && target != start;
            (!internal)
                .then(|| program.describe_code(bytes, target))
                .flatten()
        } else {
            match formed {
                Some(Formed::Address(formed)) | Some(Formed::Load(formed)) => {
                    program.describe_data(bytes, formed)
                }
                None => None,
            }
        };
        if flow == FlowKind::Call {
            pages.clear();
        }
        if let Some(target) = target
            && matches!(flow, FlowKind::Jump | FlowKind::ConditionalJump)
        {
            extent.branch(target, start, window_end);
        }
        // The decoder prints PC-relative operands as offsets; show the address.
        let mut text = raw.to_string();
        let absolute = pc_offset(&raw).map(|offset| {
            let base = if raw.opcode == Opcode::ADRP {
                address & !0xfff
            } else {
                address
            };
            base.wrapping_add(offset as u64)
        });
        if let Some(absolute) = absolute
            && let Some(position) = text.rfind('$')
        {
            let end = text[position..]
                .find([',', ' ', ']'])
                .map_or(text.len(), |length| position + length);
            text.replace_range(position..end, &format!("0x{absolute:x}"));
        }
        instructions.push(Instruction {
            address,
            bytes: chunk.to_vec(),
            text,
            flow,
            target,
            comment,
        });
        if infer_end
            && matches!(flow, FlowKind::Return | FlowKind::Jump)
            && extent.ends_at(address + 4)
        {
            return (instructions, Decoded::Returned);
        }
    }
    (instructions, Decoded::RanOut)
}
