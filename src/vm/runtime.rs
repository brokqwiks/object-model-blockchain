use crate::core::{address::Address, object_address::ObjectAddress, owner::Owner};
use serde_json::Value;

use super::{bytecode::Instruction, contract::Contract};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmError {
    StepLimitExceeded,
    StackUnderflow,
    DivisionByZero,
    MissingArgument,
    InvalidJsonArgs,
    InvalidArgumentType,
    InvalidJump,
    PermissionDenied,
    ObjectNotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmExecutionOutcome {
    pub steps_used: u32,
    pub writes: usize,
    pub events: Vec<String>,
}

pub trait VmHost {
    fn owner_of_object(&self, address: ObjectAddress) -> Option<Owner>;
    fn version_of_object(&self, address: ObjectAddress) -> Option<u64>;
}

pub fn execute_contract(
    contract: &mut Contract,
    host: &impl VmHost,
    sender: Address,
    call_args_json: &str,
    max_steps: u32,
) -> Result<VmExecutionOutcome, VmError> {
    let args: Value = serde_json::from_str(call_args_json).map_err(|_| VmError::InvalidJsonArgs)?;
    if !args.is_array() {
        return Err(VmError::InvalidJsonArgs);
    }

    let mut pc: usize = 0;
    let mut steps: u32 = 0;
    let mut stack: Vec<i64> = Vec::new();
    let mut writes = 0usize;
    let mut events: Vec<String> = Vec::new();

    while pc < contract.bytecode.len() {
        if steps >= max_steps {
            return Err(VmError::StepLimitExceeded);
        }
        steps = steps.saturating_add(1);

        let instruction = contract.bytecode[pc].clone();
        pc = pc.saturating_add(1);

        match instruction {
            Instruction::Halt => break,
            Instruction::PushI64(value) => stack.push(value),
            Instruction::PushArg(index) => {
                let Some(value) = args.get(index) else {
                    return Err(VmError::MissingArgument);
                };
                let Some(as_i64) = value.as_i64() else {
                    return Err(VmError::InvalidArgumentType);
                };
                stack.push(as_i64);
            }
            Instruction::Load(key) => {
                stack.push(contract.storage_value(&key));
            }
            Instruction::Store(key) => {
                let value = pop(&mut stack)?;
                contract.set_storage_value(key, value);
                writes = writes.saturating_add(1);
            }
            Instruction::Add => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(a.saturating_add(b));
            }
            Instruction::Sub => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(a.saturating_sub(b));
            }
            Instruction::Mul => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(a.saturating_mul(b));
            }
            Instruction::Div => {
                let b = pop(&mut stack)?;
                if b == 0 {
                    return Err(VmError::DivisionByZero);
                }
                let a = pop(&mut stack)?;
                stack.push(a / b);
            }
            Instruction::Eq => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(if a == b { 1 } else { 0 });
            }
            Instruction::Gt => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(if a > b { 1 } else { 0 });
            }
            Instruction::Lt => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(if a < b { 1 } else { 0 });
            }
            Instruction::Jump(target) => {
                if target >= contract.bytecode.len() {
                    return Err(VmError::InvalidJump);
                }
                pc = target;
            }
            Instruction::JumpIfZero(target) => {
                let value = pop(&mut stack)?;
                if value == 0 {
                    if target >= contract.bytecode.len() {
                        return Err(VmError::InvalidJump);
                    }
                    pc = target;
                }
            }
            Instruction::AssertSenderIsOwner => {
                if contract.owner() != Owner::Address(sender) {
                    return Err(VmError::PermissionDenied);
                }
            }
            Instruction::Emit(message) => {
                let event = format!("{}:{}", contract.name, message);
                contract.append_event(event.clone());
                events.push(event);
            }
            Instruction::PushObjectVersion(address) => {
                let Some(version) = host.version_of_object(address) else {
                    return Err(VmError::ObjectNotFound);
                };
                stack.push(version as i64);
            }
            Instruction::RequireObjectOwnedBySender(address) => {
                let Some(owner) = host.owner_of_object(address) else {
                    return Err(VmError::ObjectNotFound);
                };
                if owner != Owner::Address(sender) {
                    return Err(VmError::PermissionDenied);
                }
            }
        }
    }

    if writes > 0 {
        contract.bump_version();
    }

    Ok(VmExecutionOutcome {
        steps_used: steps,
        writes,
        events,
    })
}

fn pop(stack: &mut Vec<i64>) -> Result<i64, VmError> {
    stack.pop().ok_or(VmError::StackUnderflow)
}
