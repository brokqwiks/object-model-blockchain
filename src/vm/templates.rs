use crate::core::object_address::ObjectAddress;
use crate::core::owner::Owner;

use super::{bytecode::Instruction, contract::Contract};

pub const TEMPLATE_COUNTER: u8 = 1;
pub const TEMPLATE_GUARDED_MIRROR: u8 = 2;

pub fn template_name(template_id: u8) -> Option<&'static str> {
    match template_id {
        TEMPLATE_COUNTER => Some("counter"),
        TEMPLATE_GUARDED_MIRROR => Some("guarded_mirror"),
        _ => None,
    }
}

pub fn template_id_by_name(name: &str) -> Option<u8> {
    match name {
        "counter" => Some(TEMPLATE_COUNTER),
        "guarded_mirror" => Some(TEMPLATE_GUARDED_MIRROR),
        _ => None,
    }
}

pub fn build_contract(
    template_id: u8,
    owner: Owner,
    object_address: ObjectAddress,
) -> Option<Contract> {
    match template_id {
        TEMPLATE_COUNTER => Some(Contract::new(
            owner,
            object_address,
            template_id,
            "counter",
            counter_bytecode(),
        )),
        TEMPLATE_GUARDED_MIRROR => Some(Contract::new(
            owner,
            object_address,
            template_id,
            "guarded_mirror",
            guarded_mirror_bytecode(),
        )),
        _ => None,
    }
}

fn counter_bytecode() -> Vec<Instruction> {
    vec![
        Instruction::AssertSenderIsOwner,
        Instruction::Load("counter".to_string()),
        Instruction::PushArg(0),
        Instruction::Add,
        Instruction::Store("counter".to_string()),
        Instruction::Emit("counter_updated".to_string()),
        Instruction::Halt,
    ]
}

fn guarded_mirror_bytecode() -> Vec<Instruction> {
    vec![
        Instruction::AssertSenderIsOwner,
        Instruction::PushArg(0),
        Instruction::Store("last_value".to_string()),
        Instruction::Emit("value_mirrored".to_string()),
        Instruction::Halt,
    ]
}
