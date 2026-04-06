mod core;
mod crypto;
mod object_standards;

use crate::core::{
    address::{Address, NETWORK_TESTNET},
    object::Object,
    owner::Owner,
    state::State,
    tx::{Effect, Transaction},
};
use crate::crypto::keys::Keypair;
use crate::object_standards::token::BasicToken;

fn main() {
    let sender_keypair = Keypair::generate();
    let recipient_keypair = Keypair::generate();
    let sender = Address::from_public_key(&sender_keypair.verifying_key_bytes(), NETWORK_TESTNET);
    let recipient =
        Address::from_public_key(&recipient_keypair.verifying_key_bytes(), NETWORK_TESTNET);

    let object = Object::new(Owner::Address(sender));
    let object_address = object.object_address();
    let mut token = BasicToken::new("LYX Coin", "LYX", 9, "Native token demo", Some(1_000_000_000_000));
    let coin = token.mint(sender, 1_000_000).expect("mint should succeed");
    let coin_address = coin.object_address;

    let mut state = State::new();
    state.insert_object(object);
    state.insert_coin(coin);

    let tx = Transaction::new_unsigned(
        sender_keypair.verifying_key_bytes(),
        sender,
        0,
        vec![
            Effect::TransferObject {
                object_address,
                new_owner: recipient,
            },
            Effect::TransferCoin {
                coin_address,
                new_owner: recipient,
            },
        ],
    )
    .sign(&sender_keypair)
    .expect("tx signing failed");

    state.apply_tx(&tx).expect("tx apply should succeed");

    let moved_object = state
        .get_object(object_address)
        .expect("object should exist");
    let moved_coin = state.get_coin(coin_address).expect("coin should exist");

    println!("object address: {}", moved_object.object_address().to_hex());
    println!("coin address: {}", moved_coin.object_address.to_hex());
    println!("object owner: {}", moved_object.owner().to_hex());
    println!("coin owner: {}", moved_coin.owner.to_hex());
    println!(
        "transaction json:\n{}",
        tx.to_json_pretty()
            .expect("transaction json serialization failed")
    );
}
