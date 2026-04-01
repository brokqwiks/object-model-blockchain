use crate::core::address::Address;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryCap {
    pub token_symbol: String,
    pub total_supply: u64,
    pub max_supply: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    pub id: u64,
    pub owner: Address,
    pub amount: u64,
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicToken {
    pub metadata: TokenMetadata,
    pub treasury: TreasuryCap,
    next_coin_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    MaxSupplyExceeded,
    SupplyOverflow,
    InvalidAmount,
    InsufficientBalance,
    UnauthorizedTransfer,
    CoinIdMismatch,
}

impl BasicToken {
    pub fn new(
        name: impl Into<String>,
        symbol: impl Into<String>,
        decimals: u8,
        description: impl Into<String>,
        max_supply: Option<u64>,
    ) -> Self {
        let symbol = symbol.into();
        Self {
            metadata: TokenMetadata {
                name: name.into(),
                symbol: symbol.clone(),
                decimals,
                description: description.into(),
            },
            treasury: TreasuryCap {
                token_symbol: symbol,
                total_supply: 0,
                max_supply,
            },
            next_coin_id: 1,
        }
    }

    pub fn mint(&mut self, recipient: Address, amount: u64) -> Result<Coin, TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }

        let Some(new_supply) = self.treasury.total_supply.checked_add(amount) else {
            return Err(TokenError::SupplyOverflow);
        };

        if let Some(max_supply) = self.treasury.max_supply {
            if new_supply > max_supply {
                return Err(TokenError::MaxSupplyExceeded);
            }
        }

        let coin = Coin {
            id: self.next_coin_id,
            owner: recipient,
            amount,
            version: 0,
        };
        self.next_coin_id = self.next_coin_id.saturating_add(1);
        self.treasury.total_supply = new_supply;
        Ok(coin)
    }

    pub fn burn(&mut self, coin: Coin) -> Result<(), TokenError> {
        if coin.amount == 0 {
            return Err(TokenError::InvalidAmount);
        }

        self.treasury.total_supply = self
            .treasury
            .total_supply
            .checked_sub(coin.amount)
            .ok_or(TokenError::SupplyOverflow)?;
        Ok(())
    }
}

impl Coin {
    pub fn transfer(self, sender: Address, recipient: Address) -> Result<Self, TokenError> {
        if self.owner != sender {
            return Err(TokenError::UnauthorizedTransfer);
        }

        Ok(Self {
            owner: recipient,
            version: self.version.saturating_add(1),
            ..self
        })
    }

    pub fn split(self, amount: u64, new_coin_id: u64) -> Result<(Self, Self), TokenError> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount);
        }
        if amount >= self.amount {
            return Err(TokenError::InsufficientBalance);
        }

        let remainder = Self {
            amount: self.amount - amount,
            version: self.version.saturating_add(1),
            ..self
        };

        let split = Self {
            id: new_coin_id,
            owner: self.owner,
            amount,
            version: 0,
        };

        Ok((remainder, split))
    }

    pub fn join(self, other: Self) -> Result<Self, TokenError> {
        if self.id == other.id {
            return Err(TokenError::CoinIdMismatch);
        }
        if self.owner != other.owner {
            return Err(TokenError::UnauthorizedTransfer);
        }

        let Some(amount) = self.amount.checked_add(other.amount) else {
            return Err(TokenError::SupplyOverflow);
        };

        Ok(Self {
            amount,
            version: self.version.saturating_add(1),
            ..self
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::core::address::{Address, NETWORK_TESTNET};
    use crate::crypto::keys::Keypair;
    use crate::object_standards::token::{BasicToken, TokenError};

    fn address_with_seed(seed: u8) -> Address {
        let keypair = Keypair::from_signing_key_bytes([seed; 32]);
        Address::from_public_key(&keypair.verifying_key_bytes(), NETWORK_TESTNET)
    }

    #[test]
    fn mint_transfer_and_burn_flow() {
        let mut token = BasicToken::new("SuiLike", "SUIX", 9, "Demo token", Some(1_000_000));
        let alice = address_with_seed(10);
        let bob = address_with_seed(11);

        let coin = token.mint(alice, 1_000).expect("mint should succeed");
        assert_eq!(token.treasury.total_supply, 1_000);

        let coin = coin.transfer(alice, bob).expect("transfer should succeed");
        assert_eq!(coin.owner, bob);

        token.burn(coin).expect("burn should succeed");
        assert_eq!(token.treasury.total_supply, 0);
    }

    #[test]
    fn mint_respects_max_supply() {
        let mut token = BasicToken::new("SuiLike", "SUIX", 9, "Demo token", Some(100));
        let alice = address_with_seed(12);

        let _coin = token.mint(alice, 80).expect("mint should succeed");
        let err = token.mint(alice, 30).expect_err("must exceed max supply");
        assert_eq!(err, TokenError::MaxSupplyExceeded);
    }

    #[test]
    fn split_and_join_coin() {
        let mut token = BasicToken::new("SuiLike", "SUIX", 9, "Demo token", None);
        let alice = address_with_seed(13);
        let coin = token.mint(alice, 500).expect("mint should succeed");

        let (remainder, split) = coin.split(200, 99).expect("split should succeed");
        assert_eq!(remainder.amount, 300);
        assert_eq!(split.amount, 200);

        let joined = remainder.join(split).expect("join should succeed");
        assert_eq!(joined.amount, 500);
    }
}
