use crate::core::object_address::ObjectAddress;
use crate::core::owner::Owner;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipError {
    NotOwner,
    NoStateChange,
}

pub trait Ownable {
    fn owner(&self) -> Owner;
    fn set_owner(&mut self, owner: Owner);
    fn bump_version(&mut self);

    fn transfer_ownership(
        &mut self,
        sender: Owner,
        recipient: Owner,
    ) -> Result<(), OwnershipError> {
        if self.owner() != sender {
            return Err(OwnershipError::NotOwner);
        }
        if sender == recipient {
            return Err(OwnershipError::NoStateChange);
        }

        self.set_owner(recipient);
        self.bump_version();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Object {
    object_address: ObjectAddress,
    owner: Owner,
    version: u64,
}

impl Object {
    pub fn new(owner: Owner) -> Object {
        Object {
            object_address: ObjectAddress::new_unique(),
            owner,
            version: 0,
        }
    }

    pub fn owner(&self) -> Owner {
        self.owner
    }

    pub fn object_address(&self) -> ObjectAddress {
        self.object_address
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

impl Ownable for Object {
    fn owner(&self) -> Owner {
        self.owner
    }

    fn set_owner(&mut self, owner: Owner) {
        self.owner = owner;
    }

    fn bump_version(&mut self) {
        self.version = self.version.saturating_add(1);
    }
}
