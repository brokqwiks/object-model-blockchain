mod core;
mod crypto;
mod object_standards;
mod vm;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::core::{
    address::Address,
    object_address::ObjectAddress,
    state::{State, StateError},
    tx::{ContractCode, Effect, Transaction},
};
use crate::crypto::keys::MasterAccountKeyManager;
use crate::object_standards::token::BasicToken;
use crate::vm::bytecode::Instruction;
use crate::vm::templates;

const DEFAULT_DB_PATH: &str = "./data/state.db";
const DEFAULT_WALLETS_PATH: &str = "./data/wallets.json";
const DEFAULT_NETWORK: u8 = 0x01;
const DEFAULT_POOL_SIZE: usize = 1024;
const GENESIS_ALIAS: &str = "genesis";
const GENESIS_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const GENESIS_SUPPLY: u64 = 1_000_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletEntry {
    mnemonic: Option<String>,
    master_secret_hex: Option<String>,
    network: u8,
    pool_size: usize,
    next_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyWalletEntryV1 {
    mnemonic: String,
    network: u8,
    pool_size: usize,
    next_index: u64,
}

fn main() {
    if let Err(err) = run_repl() {
        eprintln!("fatal error: {err}");
        std::process::exit(1);
    }
}

fn run_repl() -> Result<(), String> {
    ensure_parent_dir(DEFAULT_WALLETS_PATH)?;

    let mut wallets = load_wallets(DEFAULT_WALLETS_PATH)?;
    let mut state = State::load_or_create(DEFAULT_DB_PATH, 1)
        .map_err(|e| format!("state load/create failed: {e:?}"))?;

    ensure_genesis(&mut state, &mut wallets)?;
    persist_all(&state, &wallets)?;

    println!("Object Model Blockchain REPL");
    println!("DB: {DEFAULT_DB_PATH}");
    println!("Wallets: {DEFAULT_WALLETS_PATH}");
    println!("Type `help` for commands.");
    println!("Process is persistent; close window or press Ctrl+C to stop.");

    let mut stdin_closed = false;
    loop {
        if !stdin_closed {
            print!("om-chain> ");
            io::stdout()
                .flush()
                .map_err(|e| format!("flush failed: {e}"))?;
        }

        let mut line = String::new();
        if io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("read failed: {e}"))?
            == 0
        {
            if !stdin_closed {
                eprintln!("stdin closed: waiting for manual process stop (Ctrl+C).");
                stdin_closed = true;
            }
            thread::sleep(Duration::from_millis(500));
            continue;
        }
        stdin_closed = false;

        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("exit") || line.eq_ignore_ascii_case("quit") {
            println!("REPL does not exit by command. Use Ctrl+C or close the terminal.");
            continue;
        }

        if let Err(err) = execute_command(line, &mut state, &mut wallets) {
            eprintln!("error: {err}");
        } else {
            persist_all(&state, &wallets)?;
        }
    }
}

fn execute_command(
    line: &str,
    state: &mut State,
    wallets: &mut HashMap<String, WalletEntry>,
) -> Result<(), String> {
    if let Some(rest) = line.strip_prefix("wallet import-mnemonic ") {
        let mut parts = rest.splitn(2, ' ');
        let name = parts
            .next()
            .ok_or_else(|| "usage: wallet import-mnemonic <name> <mnemonic...>".to_string())?;
        let mnemonic = parts
            .next()
            .ok_or_else(|| "usage: wallet import-mnemonic <name> <mnemonic...>".to_string())?
            .trim();
        if wallets.contains_key(name) {
            return Err(format!("wallet `{}` already exists", name));
        }
        let manager = MasterAccountKeyManager::from_mnemonic_phrase(
            mnemonic,
            DEFAULT_NETWORK,
            DEFAULT_POOL_SIZE,
        )
        .map_err(|e| format!("invalid mnemonic: {e:?}"))?;
        wallets.insert(
            name.to_string(),
            WalletEntry {
                mnemonic: Some(mnemonic.to_string()),
                master_secret_hex: None,
                network: DEFAULT_NETWORK,
                pool_size: DEFAULT_POOL_SIZE,
                next_index: 0,
            },
        );
        println!("wallet `{name}` imported");
        println!("address: {}", manager.account_address().to_hex());
        println!("one_time_root: {}", hex::encode(manager.one_time_root()));
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix("contract call ") {
        return handle_contract_call(rest, state, wallets);
    }
    if let Some(rest) = line.strip_prefix("contract publish-custom ") {
        return handle_publish_custom(rest, state, wallets);
    }

    let parts = line.split_whitespace().collect::<Vec<_>>();
    match parts.as_slice() {
        ["help"] => {
            print_help();
            Ok(())
        }
        ["show-state"] => {
            let s = state.summary();
            println!("chain_id: {}", s.chain_id);
            println!("genesis_applied: {}", s.genesis_applied);
            println!("objects: {}", s.objects);
            println!("coins: {}", s.coins);
            println!("contracts: {}", s.contracts);
            println!("accounts_with_nonces: {}", s.accounts_with_nonces);
            println!("accounts_with_roots: {}", s.accounts_with_roots);
            println!("transactions: {}", s.transactions);
            Ok(())
        }
        ["contract", "templates"] => {
            println!("available templates:");
            println!("  counter");
            println!("  guarded_mirror");
            Ok(())
        }
        ["contract", "publish", from_wallet, template_name] => {
            let template_id = templates::template_id_by_name(template_name)
                .ok_or_else(|| "unknown template. use `contract templates`".to_string())?;

            let entry = wallets
                .get_mut(*from_wallet)
                .ok_or_else(|| format!("wallet `{}` not found", from_wallet))?;
            let mut sender_manager = manager_from_entry(entry)?;
            sender_manager.set_next_index(entry.next_index);
            let sender = sender_manager.account_address();

            match state.register_one_time_root(sender, sender_manager.one_time_root()) {
                Ok(()) => {}
                Err(StateError::OneTimeRootAlreadyRegistered) => {}
                Err(e) => return Err(format!("root register failed: {e:?}")),
            }

            let signer = sender_manager
                .issue_one_time_signer()
                .map_err(|e| format!("one-time signer issue failed: {e:?}"))?;

            let contract_address = ObjectAddress::new_unique();
            let tx = Transaction::new_unsigned(
                &signer,
                state.chain_id(),
                state.nonce_of(sender),
                vec![Effect::PublishContract {
                    contract_address,
                    code: ContractCode::Template { template_id },
                }],
            )
            .sign(&signer)
            .map_err(|e| format!("tx signing failed: {e:?}"))?;

            state
                .apply_tx(&tx)
                .map_err(|e| format!("tx apply failed: {e:?}"))?;

            entry.next_index = sender_manager.next_index();
            println!("contract published");
            println!("template: {template_name}");
            println!("address: {}", contract_address.to_hex());
            println!(
                "{}",
                tx.to_json_pretty()
                    .map_err(|e| format!("tx json failed: {e}"))?
            );
            Ok(())
        }
        ["wallet", "new", name] => {
            if wallets.contains_key(*name) {
                return Err(format!("wallet `{}` already exists", name));
            }
            let (mnemonic, manager) = MasterAccountKeyManager::new_from_random_mnemonic(
                DEFAULT_NETWORK,
                DEFAULT_POOL_SIZE,
            )
            .map_err(|e| format!("wallet generation failed: {e:?}"))?;
            let address = manager.account_address();
            let root = manager.one_time_root();
            wallets.insert(
                (*name).to_string(),
                WalletEntry {
                    mnemonic: Some(mnemonic.clone()),
                    master_secret_hex: None,
                    network: DEFAULT_NETWORK,
                    pool_size: DEFAULT_POOL_SIZE,
                    next_index: 0,
                },
            );
            println!("wallet `{name}` created");
            println!("mnemonic: {mnemonic}");
            println!("address: {}", address.to_hex());
            println!("one_time_root: {}", hex::encode(root));
            Ok(())
        }
        ["wallet", "list"] => {
            if wallets.is_empty() {
                println!("no wallets");
                return Ok(());
            }
            for (name, entry) in wallets.iter() {
                let manager = manager_from_entry(entry)?;
                println!(
                    "{} => address: {}, next_index: {}",
                    name,
                    manager.account_address().to_hex(),
                    entry.next_index
                );
            }
            Ok(())
        }
        ["wallet", "show", name] => {
            let entry = wallets
                .get(*name)
                .ok_or_else(|| format!("wallet `{}` not found", name))?;
            let manager = manager_from_entry(entry)?;
            println!("wallet: {name}");
            match (&entry.mnemonic, &entry.master_secret_hex) {
                (Some(m), _) => println!("mnemonic: {m}"),
                (_, Some(secret)) => println!("master_secret_hex: {secret}"),
                _ => println!("wallet material: <none>"),
            }
            println!("address: {}", manager.account_address().to_hex());
            println!("one_time_root: {}", hex::encode(manager.one_time_root()));
            println!("next_index: {}", entry.next_index);
            Ok(())
        }
        ["wallet", "import-secret", name, secret_hex] => {
            if wallets.contains_key(*name) {
                return Err(format!("wallet `{}` already exists", name));
            }
            let secret = parse_hex_32(secret_hex)?;
            let manager = MasterAccountKeyManager::from_master_secret(
                secret,
                DEFAULT_NETWORK,
                DEFAULT_POOL_SIZE,
            )
            .map_err(|e| format!("invalid secret: {e:?}"))?;
            wallets.insert(
                (*name).to_string(),
                WalletEntry {
                    mnemonic: None,
                    master_secret_hex: Some((*secret_hex).to_string()),
                    network: DEFAULT_NETWORK,
                    pool_size: DEFAULT_POOL_SIZE,
                    next_index: 0,
                },
            );
            println!("wallet `{name}` imported");
            println!("address: {}", manager.account_address().to_hex());
            println!("one_time_root: {}", hex::encode(manager.one_time_root()));
            Ok(())
        }
        ["wallet", "export", name] => {
            let entry = wallets
                .get(*name)
                .ok_or_else(|| format!("wallet `{}` not found", name))?;
            println!("wallet: {name}");
            if let Some(mnemonic) = &entry.mnemonic {
                println!("mnemonic: {mnemonic}");
            }
            if let Some(secret_hex) = &entry.master_secret_hex {
                println!("master_secret_hex: {secret_hex}");
            }
            println!("network: {}", entry.network);
            println!("pool_size: {}", entry.pool_size);
            println!("next_index: {}", entry.next_index);
            Ok(())
        }
        ["balance", target] => {
            let address = if let Some(name) = target.strip_prefix("wallet:") {
                let entry = wallets
                    .get(name)
                    .ok_or_else(|| format!("wallet `{}` not found", name))?;
                manager_from_entry(entry)?.account_address()
            } else {
                Address::from_hex(target).map_err(|e| format!("invalid address: {e}"))?
            };
            let balance = state.balance_of(address);
            println!("address: {}", address.to_hex());
            println!("balance: {balance}");
            Ok(())
        }
        ["send", from_wallet, to_address_hex, amount_str] => {
            let amount = amount_str
                .parse::<u64>()
                .map_err(|e| format!("invalid amount: {e}"))?;
            if amount == 0 {
                return Err("amount must be > 0".to_string());
            }

            let entry = wallets
                .get_mut(*from_wallet)
                .ok_or_else(|| format!("wallet `{}` not found", from_wallet))?;
            let mut sender_manager = manager_from_entry(entry)?;
            sender_manager.set_next_index(entry.next_index);
            let sender = sender_manager.account_address();
            let recipient =
                Address::from_hex(to_address_hex).map_err(|e| format!("invalid recipient: {e}"))?;

            match state.register_one_time_root(sender, sender_manager.one_time_root()) {
                Ok(()) => {}
                Err(StateError::OneTimeRootAlreadyRegistered) => {}
                Err(e) => return Err(format!("root register failed: {e:?}")),
            }

            let source_coin = state
                .first_coin_covering(sender, amount)
                .ok_or_else(|| "no spendable coin with requested amount".to_string())?;

            let signer = sender_manager
                .issue_one_time_signer()
                .map_err(|e| format!("one-time signer issue failed: {e:?}"))?;

            let recipient_coin_address = ObjectAddress::new_unique();
            let change_coin_address = if source_coin.amount > amount {
                Some(ObjectAddress::new_unique())
            } else {
                None
            };

            let tx = Transaction::new_unsigned(
                &signer,
                state.chain_id(),
                state.nonce_of(sender),
                vec![Effect::TransferCoinAmount {
                    from_coin_address: source_coin.object_address,
                    amount,
                    recipient,
                    recipient_coin_address,
                    change_coin_address,
                }],
            )
            .sign(&signer)
            .map_err(|e| format!("tx signing failed: {e:?}"))?;

            state
                .apply_tx(&tx)
                .map_err(|e| format!("tx apply failed: {e:?}"))?;

            entry.next_index = sender_manager.next_index();
            println!("tx applied");
            println!(
                "{}",
                tx.to_json_pretty()
                    .map_err(|e| format!("tx json failed: {e}"))?
            );
            println!("sender balance: {}", state.balance_of(sender));
            println!("recipient balance: {}", state.balance_of(recipient));
            Ok(())
        }
        ["tx", "list"] => {
            for tx in state.tx_history(20) {
                println!(
                    "#{} sender={} nonce={} otk_index={} effects={:?}",
                    tx.id, tx.sender, tx.nonce, tx.one_time_index, tx.effect_kinds
                );
            }
            Ok(())
        }
        ["tx", "list", "all"] => {
            for tx in state.tx_history_all() {
                println!(
                    "#{} sender={} nonce={} otk_index={} effects={:?}",
                    tx.id, tx.sender, tx.nonce, tx.one_time_index, tx.effect_kinds
                );
            }
            Ok(())
        }
        ["tx", "list", limit_str] => {
            let limit = limit_str
                .parse::<usize>()
                .map_err(|e| format!("invalid limit: {e}"))?;
            for tx in state.tx_history(limit) {
                println!(
                    "#{} sender={} nonce={} otk_index={} effects={:?}",
                    tx.id, tx.sender, tx.nonce, tx.one_time_index, tx.effect_kinds
                );
            }
            Ok(())
        }
        ["tx", "dump"] => {
            let json = serde_json::to_string_pretty(&state.tx_history_all())
                .map_err(|e| format!("tx dump encode failed: {e}"))?;
            println!("{json}");
            Ok(())
        }
        ["tx", "show", id_str] => {
            let id = id_str
                .parse::<u64>()
                .map_err(|e| format!("invalid tx id: {e}"))?;
            let tx = state
                .tx_by_id(id)
                .ok_or_else(|| format!("tx #{} not found", id))?;
            println!(
                "id={} chain_id={} sender={} nonce={} one_time_index={} effects_len={} effects={:?}",
                tx.id,
                tx.chain_id,
                tx.sender,
                tx.nonce,
                tx.one_time_index,
                tx.effects_len,
                tx.effect_kinds
            );
            Ok(())
        }
        ["genesis", "show"] => {
            let entry = wallets
                .get(GENESIS_ALIAS)
                .ok_or_else(|| "genesis wallet missing".to_string())?;
            let manager = manager_from_entry(entry)?;
            if let Some(mnemonic) = &entry.mnemonic {
                println!("genesis mnemonic: {mnemonic}");
            }
            println!("genesis address: {}", manager.account_address().to_hex());
            println!("genesis root: {}", hex::encode(manager.one_time_root()));
            println!(
                "genesis balance: {}",
                state.balance_of(manager.account_address())
            );
            Ok(())
        }
        ["spectator", "object", object_address_hex] | ["spectator", object_address_hex] => {
            let object_address = ObjectAddress::from_hex(object_address_hex)?;
            if let Some(object) = state.get_object(object_address) {
                let json = serde_json::to_string_pretty(object)
                    .map_err(|e| format!("object encode failed: {e}"))?;
                println!("kind: object");
                println!("{json}");
                return Ok(());
            }
            if let Some(coin) = state.get_coin(object_address) {
                let json = serde_json::to_string_pretty(coin)
                    .map_err(|e| format!("coin encode failed: {e}"))?;
                println!("kind: coin");
                println!("{json}");
                return Ok(());
            }
            if let Some(contract) = state.get_contract(object_address) {
                let json = serde_json::to_string_pretty(contract)
                    .map_err(|e| format!("contract encode failed: {e}"))?;
                println!("kind: contract");
                println!("{json}");
                return Ok(());
            }
            Err("object not found".to_string())
        }
        ["spectator", "contract", contract_address_hex] => {
            let contract_address = ObjectAddress::from_hex(contract_address_hex)?;
            let Some(contract) = state.get_contract(contract_address) else {
                return Err("contract not found".to_string());
            };
            let json = serde_json::to_string_pretty(contract)
                .map_err(|e| format!("contract encode failed: {e}"))?;
            println!("{json}");
            Ok(())
        }
        ["spectator", "account", target] => {
            let owner = parse_account_target(target, wallets)?;
            print_account_objects(state, owner)?;
            Ok(())
        }
        ["spectator", "tx", "list"] => {
            for tx in state.tx_history(20) {
                println!(
                    "#{} sender={} nonce={} otk_index={} effects={:?}",
                    tx.id, tx.sender, tx.nonce, tx.one_time_index, tx.effect_kinds
                );
            }
            Ok(())
        }
        ["spectator", "tx", "list", "all"] => {
            for tx in state.tx_history_all() {
                println!(
                    "#{} sender={} nonce={} otk_index={} effects={:?}",
                    tx.id, tx.sender, tx.nonce, tx.one_time_index, tx.effect_kinds
                );
            }
            Ok(())
        }
        ["spectator", "tx", "show", id_str] => {
            let id = id_str
                .parse::<u64>()
                .map_err(|e| format!("invalid tx id: {e}"))?;
            let tx = state
                .tx_by_id(id)
                .ok_or_else(|| format!("tx #{} not found", id))?;
            println!(
                "id={} chain_id={} sender={} nonce={} one_time_index={} effects_len={} effects={:?}",
                tx.id,
                tx.chain_id,
                tx.sender,
                tx.nonce,
                tx.one_time_index,
                tx.effects_len,
                tx.effect_kinds
            );
            Ok(())
        }
        _ => Err("unknown command. use `help`".to_string()),
    }
}

fn ensure_genesis(
    state: &mut State,
    wallets: &mut HashMap<String, WalletEntry>,
) -> Result<(), String> {
    if state.is_genesis_applied() {
        return Ok(());
    }

    let genesis_manager = MasterAccountKeyManager::from_mnemonic_phrase(
        GENESIS_MNEMONIC,
        DEFAULT_NETWORK,
        DEFAULT_POOL_SIZE,
    )
    .map_err(|e| format!("genesis mnemonic invalid: {e:?}"))?;
    let genesis_address = genesis_manager.account_address();

    match state.register_one_time_root(genesis_address, genesis_manager.one_time_root()) {
        Ok(()) => {}
        Err(StateError::OneTimeRootAlreadyRegistered) => {}
        Err(e) => return Err(format!("genesis root register failed: {e:?}")),
    }

    let mut token = BasicToken::new(
        "Genesis Coin",
        "GEN",
        9,
        "Genesis allocation token",
        Some(1_000_000_000_000),
    );
    let genesis_coin = token
        .mint(genesis_address, GENESIS_SUPPLY)
        .map_err(|e| format!("genesis mint failed: {e:?}"))?;
    state.insert_coin(genesis_coin);
    state.mark_genesis_applied();

    wallets.insert(
        GENESIS_ALIAS.to_string(),
        WalletEntry {
            mnemonic: Some(GENESIS_MNEMONIC.to_string()),
            master_secret_hex: None,
            network: DEFAULT_NETWORK,
            pool_size: DEFAULT_POOL_SIZE,
            next_index: 0,
        },
    );

    println!("genesis applied");
    println!("genesis address: {}", genesis_address.to_hex());
    println!("genesis minted: {}", GENESIS_SUPPLY);
    println!("genesis mnemonic: {}", GENESIS_MNEMONIC);
    Ok(())
}

fn manager_from_entry(entry: &WalletEntry) -> Result<MasterAccountKeyManager, String> {
    if let Some(mnemonic) = &entry.mnemonic {
        return MasterAccountKeyManager::from_mnemonic_phrase(
            mnemonic,
            entry.network,
            entry.pool_size,
        )
        .map_err(|e| format!("wallet restore from mnemonic failed: {e:?}"));
    }
    if let Some(secret_hex) = &entry.master_secret_hex {
        let secret = parse_hex_32(secret_hex)?;
        return MasterAccountKeyManager::from_master_secret(secret, entry.network, entry.pool_size)
            .map_err(|e| format!("wallet restore from secret failed: {e:?}"));
    }
    Err("wallet has neither mnemonic nor master secret".to_string())
}

fn load_wallets(path: &str) -> Result<HashMap<String, WalletEntry>, String> {
    if !Path::new(path).exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(path).map_err(|e| format!("wallet load failed: {e}"))?;
    if let Ok(wallets) = serde_json::from_str::<HashMap<String, WalletEntry>>(&content) {
        return Ok(wallets);
    }

    let legacy = serde_json::from_str::<HashMap<String, LegacyWalletEntryV1>>(&content)
        .map_err(|e| format!("wallet parse failed: {e}"))?;
    let migrated = legacy
        .into_iter()
        .map(|(name, entry)| {
            (
                name,
                WalletEntry {
                    mnemonic: Some(entry.mnemonic),
                    master_secret_hex: None,
                    network: entry.network,
                    pool_size: entry.pool_size,
                    next_index: entry.next_index,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    Ok(migrated)
}

fn save_wallets(path: &str, wallets: &HashMap<String, WalletEntry>) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let content =
        serde_json::to_string_pretty(wallets).map_err(|e| format!("wallet encode failed: {e}"))?;
    fs::write(path, content).map_err(|e| format!("wallet save failed: {e}"))?;
    Ok(())
}

fn persist_all(state: &State, wallets: &HashMap<String, WalletEntry>) -> Result<(), String> {
    state
        .save_to_db(DEFAULT_DB_PATH)
        .map_err(|e| format!("state save failed: {e:?}"))?;
    save_wallets(DEFAULT_WALLETS_PATH, wallets)?;
    Ok(())
}

fn ensure_parent_dir(path: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create dir {:?}: {e}", parent))?;
    }
    Ok(())
}

fn print_help() {
    println!("Core:");
    println!("  help");
    println!("  show-state");
    println!("  genesis show");
    println!();
    println!("Wallets:");
    println!("  wallet new <name>");
    println!("  wallet import-mnemonic <name> <mnemonic words...>");
    println!("  wallet import-secret <name> <master_secret_hex_64>");
    println!("  wallet export <name>");
    println!("  wallet list");
    println!("  wallet show <name>");
    println!("  balance <wallet:<name>|address_hex>");
    println!();
    println!("Transfers:");
    println!("  send <from_wallet> <to_address_hex> <amount>");
    println!();
    println!("Contracts:");
    println!("  contract templates");
    println!("  contract publish <from_wallet> <counter|guarded_mirror>");
    println!("  contract publish-custom <from_wallet> <name> <bytecode_json_path>");
    println!("  contract call <from_wallet> <contract_address_hex> [max_steps] [json_args]");
    println!();
    println!("Transactions:");
    println!("  tx list");
    println!("  tx list <limit>");
    println!("  tx list all");
    println!("  tx show <id>");
    println!("  tx dump");
    println!();
    println!("Spectator:");
    println!("  spectator <object_address_hex>");
    println!("  spectator object <object_address_hex>");
    println!("  spectator contract <contract_address_hex>");
    println!("  spectator account <wallet:<name>|address_hex>");
    println!("  spectator tx list");
    println!("  spectator tx list all");
    println!("  spectator tx show <id>");
}

fn handle_contract_call(
    rest: &str,
    state: &mut State,
    wallets: &mut HashMap<String, WalletEntry>,
) -> Result<(), String> {
    let mut first_split = rest.splitn(3, ' ');
    let from_wallet = first_split
        .next()
        .ok_or_else(|| {
            "usage: contract call <from_wallet> <contract_address_hex> [max_steps] [json_args]"
                .to_string()
        })?
        .trim();
    let contract_hex = first_split
        .next()
        .ok_or_else(|| {
            "usage: contract call <from_wallet> <contract_address_hex> [max_steps] [json_args]"
                .to_string()
        })?
        .trim();
    if from_wallet.is_empty() || contract_hex.is_empty() {
        return Err(
            "usage: contract call <from_wallet> <contract_address_hex> [max_steps] [json_args]"
                .to_string(),
        );
    }
    let contract_address = ObjectAddress::from_hex(contract_hex)?;
    let tail = first_split.next().unwrap_or("").trim();

    let mut max_steps = 10_000u32;
    let mut call_args_json = "[]".to_string();
    if !tail.is_empty() {
        let mut tail_parts = tail.splitn(2, ' ');
        let first = tail_parts.next().unwrap_or("");
        if let Ok(parsed) = first.parse::<u32>() {
            max_steps = parsed;
            let rest_json = tail_parts.next().unwrap_or("").trim();
            if !rest_json.is_empty() {
                call_args_json = rest_json.to_string();
            }
        } else {
            call_args_json = tail.to_string();
        }
    }
    serde_json::from_str::<serde_json::Value>(&call_args_json)
        .map_err(|e| format!("invalid json args: {e}"))?;

    let entry = wallets
        .get_mut(from_wallet)
        .ok_or_else(|| format!("wallet `{}` not found", from_wallet))?;
    let mut sender_manager = manager_from_entry(entry)?;
    sender_manager.set_next_index(entry.next_index);
    let sender = sender_manager.account_address();

    match state.register_one_time_root(sender, sender_manager.one_time_root()) {
        Ok(()) => {}
        Err(StateError::OneTimeRootAlreadyRegistered) => {}
        Err(e) => return Err(format!("root register failed: {e:?}")),
    }

    let signer = sender_manager
        .issue_one_time_signer()
        .map_err(|e| format!("one-time signer issue failed: {e:?}"))?;

    let tx = Transaction::new_unsigned(
        &signer,
        state.chain_id(),
        state.nonce_of(sender),
        vec![Effect::ExecuteContract {
            contract_address,
            max_steps,
            call_args_json,
        }],
    )
    .sign(&signer)
    .map_err(|e| format!("tx signing failed: {e:?}"))?;

    state
        .apply_tx(&tx)
        .map_err(|e| format!("tx apply failed: {e:?}"))?;

    entry.next_index = sender_manager.next_index();
    println!("contract call applied");
    println!(
        "{}",
        tx.to_json_pretty()
            .map_err(|e| format!("tx json failed: {e}"))?
    );
    if let Some(contract) = state.get_contract(contract_address) {
        println!("contract version: {}", contract.version());
        println!("contract owner: {:?}", contract.owner());
        println!("storage: {:?}", contract.storage);
        println!("events: {:?}", contract.event_log);
    }
    Ok(())
}

fn handle_publish_custom(
    rest: &str,
    state: &mut State,
    wallets: &mut HashMap<String, WalletEntry>,
) -> Result<(), String> {
    let mut parts = rest.splitn(3, ' ');
    let from_wallet = parts.next().ok_or_else(|| {
        "usage: contract publish-custom <from_wallet> <name> <bytecode_json_path>".to_string()
    })?;
    let name = parts.next().ok_or_else(|| {
        "usage: contract publish-custom <from_wallet> <name> <bytecode_json_path>".to_string()
    })?;
    let path = parts.next().ok_or_else(|| {
        "usage: contract publish-custom <from_wallet> <name> <bytecode_json_path>".to_string()
    })?;

    let bytecode_content =
        fs::read_to_string(path).map_err(|e| format!("failed to read bytecode file: {e}"))?;
    let bytecode = serde_json::from_str::<Vec<Instruction>>(&bytecode_content)
        .map_err(|e| format!("invalid bytecode json: {e}"))?;
    if bytecode.is_empty() {
        return Err("bytecode is empty".to_string());
    }

    let entry = wallets
        .get_mut(from_wallet)
        .ok_or_else(|| format!("wallet `{}` not found", from_wallet))?;
    let mut sender_manager = manager_from_entry(entry)?;
    sender_manager.set_next_index(entry.next_index);
    let sender = sender_manager.account_address();

    match state.register_one_time_root(sender, sender_manager.one_time_root()) {
        Ok(()) => {}
        Err(StateError::OneTimeRootAlreadyRegistered) => {}
        Err(e) => return Err(format!("root register failed: {e:?}")),
    }

    let signer = sender_manager
        .issue_one_time_signer()
        .map_err(|e| format!("one-time signer issue failed: {e:?}"))?;

    let contract_address = ObjectAddress::new_unique();
    let tx = Transaction::new_unsigned(
        &signer,
        state.chain_id(),
        state.nonce_of(sender),
        vec![Effect::PublishContract {
            contract_address,
            code: ContractCode::Custom {
                name: name.to_string(),
                bytecode,
            },
        }],
    )
    .sign(&signer)
    .map_err(|e| format!("tx signing failed: {e:?}"))?;

    state
        .apply_tx(&tx)
        .map_err(|e| format!("tx apply failed: {e:?}"))?;

    entry.next_index = sender_manager.next_index();
    println!("custom contract published");
    println!("name: {name}");
    println!("address: {}", contract_address.to_hex());
    println!(
        "{}",
        tx.to_json_pretty()
            .map_err(|e| format!("tx json failed: {e}"))?
    );
    Ok(())
}

fn parse_account_target(
    target: &str,
    wallets: &HashMap<String, WalletEntry>,
) -> Result<Address, String> {
    if let Some(name) = target.strip_prefix("wallet:") {
        let entry = wallets
            .get(name)
            .ok_or_else(|| format!("wallet `{}` not found", name))?;
        return Ok(manager_from_entry(entry)?.account_address());
    }
    Address::from_hex(target).map_err(|e| format!("invalid address: {e}"))
}

fn print_account_objects(state: &State, owner: Address) -> Result<(), String> {
    let objects = state.objects_of_owner(owner);
    let coins = state.coins_of_owner(owner);
    let contracts = state.contracts_of_owner(owner);
    println!("account: {}", owner.to_hex());
    println!("balance: {}", state.balance_of(owner));
    println!(
        "owned_counts => objects: {}, coins: {}, contracts: {}",
        objects.len(),
        coins.len(),
        contracts.len()
    );

    let objects_json =
        serde_json::to_string_pretty(&objects).map_err(|e| format!("object encode failed: {e}"))?;
    let coins_json =
        serde_json::to_string_pretty(&coins).map_err(|e| format!("coin encode failed: {e}"))?;
    let contracts_json = serde_json::to_string_pretty(&contracts)
        .map_err(|e| format!("contract encode failed: {e}"))?;

    println!("objects: {objects_json}");
    println!("coins: {coins_json}");
    println!("contracts: {contracts_json}");
    Ok(())
}

fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
