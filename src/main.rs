mod core;
mod crypto;
mod object_standards;
use crate::core::{
    address::{Address, NETWORK_TESTNET},
    object::Object,
    owner::Owner,
    state::State,
    tx::TransferTx,
};
use crate::crypto::keys::Keypair;
use crate::object_standards::token::BasicToken;

fn main() {
    let sender_keypair = Keypair::generate();
    let recipient_keypair = Keypair::generate();
    let sender = Address::from_public_key(&sender_keypair.verifying_key_bytes(), NETWORK_TESTNET);
    let recipient =
        Address::from_public_key(&recipient_keypair.verifying_key_bytes(), NETWORK_TESTNET);
    let object = Object::new(0, Owner::Address(sender));
    let mut state = State::new();
    state.insert_object(object);

    let tx = TransferTx::new_unsigned(
        sender_keypair.verifying_key_bytes(),
        sender,
        object.id(),
        recipient,
        0,
    )
    .sign(&sender_keypair)
    .expect("tx signing failed");

    state
        .apply_transfer_tx(&tx)
        .expect("tx apply should succeed");
    let updated_object = state
        .get_object(object.id())
        .expect("object should exist after tx");

    println!("object id: {}", updated_object.id());
    println!("owner: {}", updated_object.owner().to_hex());
    println!("version: {}", updated_object.version());

    let serialized = serde_json::to_string(updated_object).expect("object serialization failed");
    println!("serialized object: {serialized}");

    let hash = crate::crypto::hash::sha256(serialized.as_bytes());
    println!("object hash: {}", hex::encode(hash));
    println!(
        "transaction json:\n{}",
        tx.to_json_pretty()
            .expect("transaction json serialization failed")
    );

    println!("sender address: {}", sender.to_hex());
    println!("recipient address: {}", recipient.to_hex());

    let mut lyx_coin = BasicToken::new(
        "LYX Coin",
        "LYX",
        9,
        "Native token for LYX blockchain",
        1000000000000
    )
    .mint()

    println!("token standard json:\n{token_json}");
    println!("coin object json:\n{coin_json}");
}
