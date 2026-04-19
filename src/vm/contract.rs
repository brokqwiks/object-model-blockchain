use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::core::{
    object::{Object, Ownable},
    object_address::ObjectAddress,
    owner::Owner,
};

use super::bytecode::Instruction;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    pub object: Object,
    pub name: String,
    pub template_id: u8,
    pub bytecode: Vec<Instruction>,
    pub storage: HashMap<String, i64>,
    pub event_log: Vec<String>,
}

impl Contract {
    pub fn new(
        owner: Owner,
        object_address: ObjectAddress,
        template_id: u8,
        name: impl Into<String>,
        bytecode: Vec<Instruction>,
    ) -> Self {
        Self {
            object: Object::with_address(owner, object_address),
            name: name.into(),
            template_id,
            bytecode,
            storage: HashMap::new(),
            event_log: Vec::new(),
        }
    }

    pub fn owner(&self) -> Owner {
        self.object.owner()
    }

    pub fn object_address(&self) -> ObjectAddress {
        self.object.object_address()
    }

    pub fn version(&self) -> u64 {
        self.object.version()
    }

    pub fn storage_value(&self, key: &str) -> i64 {
        *self.storage.get(key).unwrap_or(&0)
    }

    pub fn set_storage_value(&mut self, key: String, value: i64) {
        self.storage.insert(key, value);
    }

    pub fn append_event(&mut self, event: String) {
        self.event_log.push(event);
    }

    pub fn bump_version(&mut self) {
        self.object.bump_version();
    }
}
