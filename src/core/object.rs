use crate::core::owner::Owner;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Object {
    id: u64,
    owner: Owner,
    version: u64,
}

impl Object {
    pub fn new(id: u64, owner: Owner) -> Object {
        Object {
            id,
            owner,
            version: 0,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn owner(&self) -> Owner {
        self.owner
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn transfer(&mut self, owner: Owner) {
        self.owner = owner;
        self.version = self.version.saturating_add(1);
    }
}
