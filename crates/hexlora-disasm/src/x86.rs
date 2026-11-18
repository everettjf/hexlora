//! x86 and x86-64 decoding through `iced-x86`.

use crate::{Decoded, ExtentTracker, FlowKind, Instruction, Program};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction as Raw, IntelFormatter, Mnemonic,
    OpKind, Register,
};

fn formatter() -> IntelFormatter {
    let mut formatter = IntelFormatter::new();
    let options = formatter.options_mut();
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_uppercase_hex(false);
    options.set_space_after_operand_separator(true);
    options.set_branch_leading_zeros(false);
    // Show the address an instruction refers to, not the raw displacement.
    options.set_rip_relative_addresses(false);
    formatter
}

/// The address of a memory operand that needs no register to compute: either
/// RIP-relative or a bare displacement.
fn static_memory_address(instruction: &Raw) -> Option<u64> {
    let has_memory =
        (0..instruction.op_count()).any(|op| instruction.op_kind(op) == OpKind::Memory);
    if !has_memory {
        return None;
    }
    if instruction.is_ip_rel_memory_operand() {
        return Some(instruction.ip_rel_memory_address());
    }
    (instruction.memory_base() == Register::None && instruction.memory_index() == Register::None)
        .then(|| instruction.memory_displacement64())
        .filter(|address| *address != 0)
}

/// An immediate operand that is a mapped address. 32-bit and non-PIC 64-bit
/// code pass addresses this way (`push offset str`, `mov eax, offset table`).
fn immediate_address(program: &Program, instruction: &Raw) -> Option<u64> {
    (0..instruction.op_count()).find_map(|op| {
        let value = match instruction.op_kind(op) {
            OpKind::Immediate32 => instruction.immediate32() as u64,
            OpKind::Immediate64 => instruction.immediate64(),
            _ => return None,
        };
        (value >= 0x1000 && program.region_at(value).is_some()).then_some(value)
    })
}

fn flow_of(instruction: &Raw) -> FlowKind {
    if instruction.is_invalid() {
        return FlowKind::Invalid;
    }
    match instruction.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => {
            if instruction.mnemonic() == Mnemonic::Int3 {
                FlowKind::Trap
            } else {
                FlowKind::Next
            }
        }
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => FlowKind::Jump,
        FlowControl::ConditionalBranch => FlowKind::ConditionalJump,
        FlowControl::Return => FlowKind::Return,
        FlowControl::Call | FlowControl::IndirectCall => FlowKind::Call,
        FlowControl::Interrupt | FlowControl::Exception => FlowKind::Trap,
    }
}

fn direct_target(instruction: &Raw) -> Option<u64> {
    (0..instruction.op_count()).find_map(|op| {
        matches!(
            instruction.op_kind(op),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
        .then(|| instruction.near_branch_target())
    })
}

fn bitness(program: &Program) -> u32 {
    match program.architecture {
        crate::Architecture::X86 => 32,
        _ => 64,
    }
}

/// If `address` holds a stub that only jumps through an import slot, returns
/// the import's name. Covers PE thunks, ELF PLT entries, and Mach-O stubs.
pub(crate) fn stub_target<'p>(program: &'p Program, bytes: &[u8], address: u64) -> Option<&'p str> {
    if !program.is_code(address) {
        return None;
    }
    let window = program.bytes_at(bytes, address, 32)?;
    let mut decoder = Decoder::with_ip(bitness(program), window, address, DecoderOptions::NONE);
    let mut instruction = Raw::default();
    // An `endbr` landing pad, and in IBT-enabled PLTs a `bnd` prefix, can
    // precede the jump.
    for _ in 0..3 {
        if !decoder.can_decode() {
            return None;
        }
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            return None;
        }
        match instruction.flow_control() {
            // Anything else before the jump makes this a wrapper function,
            // not a stub.
            FlowControl::Next
                if matches!(
                    instruction.mnemonic(),
                    Mnemonic::Endbr64 | Mnemonic::Endbr32
                ) =>
            {
                continue;
            }
            FlowControl::IndirectBranch => {
                return static_memory_address(&instruction)
                    .and_then(|slot| program.import_at(slot));
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
    bits: u32,
) -> (Vec<Instruction>, Decoded) {
    let window_end = start + window.len() as u64;
    let mut decoder = Decoder::with_ip(bits, window, start, DecoderOptions::NONE);
    let mut formatter = formatter();
    let mut raw = Raw::default();
    let mut extent = ExtentTracker::default();
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        if instructions.len() >= max {
            return (instructions, Decoded::Limit);
        }
        let offset = decoder.position();
        decoder.decode_out(&mut raw);
        let length = raw.len().max(1);
        let encoded = window[offset..(offset + length).min(window.len())].to_vec();
        let address = raw.ip();
        let flow = flow_of(&raw);
        let mut text = String::new();
        if flow == FlowKind::Invalid {
            text.push_str("(bad)");
        } else {
            formatter.format(&raw, &mut text);
        }
        let target = direct_target(&raw).filter(|_| flow != FlowKind::Invalid);
        let comment = if flow == FlowKind::Invalid {
            None
        } else if let Some(target) = target {
            // Jumps inside the function being listed need no label.
            let internal =
                flow != FlowKind::Call && target >= start && target < window_end && target != start;
            (!internal)
                .then(|| program.describe_code(bytes, target))
                .flatten()
        } else if let Some(address) = static_memory_address(&raw) {
            program.describe_data(bytes, address)
        } else {
            immediate_address(program, &raw)
                .and_then(|address| program.describe_constant(bytes, address))
        };
        if let Some(target) = target
            && matches!(flow, FlowKind::Jump | FlowKind::ConditionalJump)
        {
            extent.branch(target, start, window_end);
        }
        let next = address + length as u64;
        instructions.push(Instruction {
            address,
            bytes: encoded,
            text,
            flow,
            target,
            comment,
        });
        if infer_end && matches!(flow, FlowKind::Return | FlowKind::Jump) && extent.ends_at(next) {
            return (instructions, Decoded::Returned);
        }
    }
    (instructions, Decoded::RanOut)
}
