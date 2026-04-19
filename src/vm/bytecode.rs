use crate::core::object_address::ObjectAddress;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    Halt,
    PushI64(i64),
    PushArg(usize),
    Load(String),
    Store(String),
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Gt,
    Lt,
    Jump(usize),
    JumpIfZero(usize),
    AssertSenderIsOwner,
    Emit(String),
    PushObjectVersion(ObjectAddress),
    RequireObjectOwnedBySender(ObjectAddress),
}
