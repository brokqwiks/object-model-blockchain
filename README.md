# Object Model Blockchain (Educational)

> Minimal educational blockchain runtime with an object model, one-time signer authorization, and RocksDB-backed state.

---

## Русский

### Идея проекта
Это учебный runtime блокчейна с объектной моделью:
- состояние хранится как объекты и coin-объекты,
- транзакции содержат эффекты (`effects`),
- право изменения проверяется на уровне state,
- для подписи используется схема **одноразовых ключей (OTK)** без раскрытия master public key в транзакции.

### Концепция безопасности одноразовых ключей
1. У аккаунта есть пул одноразовых ключей.
2. Из их публичных ключей строится Merkle-дерево.
3. В state для аккаунта регистрируется только `one_time_root`.
4. В транзакции передаются:
   - `one_time_public_key`,
   - `one_time_index`,
   - `one_time_merkle_proof`,
   - подпись этим одноразовым ключом.
5. Узел проверяет:
   - валидность подписи,
   - membership proof к root аккаунта,
   - одноразовый индекс не использован ранее,
   - nonce,
   - ownership для каждого эффекта.

Так достигается цель: **master public key не публикуется в tx**.

### Что реализовано
- Object model (`Object`, `Coin`, `Owner`, `ObjectAddress`).
- Transaction effects:
  - `TransferObject`
  - `TransferCoin`
  - `RotateOneTimeRoot`
- Domain separation в подписи tx:
  - `TX_INTENT_V1`
  - `chain_id`
  - `tx_version`
- Защиты:
  - anti-replay (`nonce`),
  - one-time reuse protection,
  - лимит размера proof,
  - лимит количества effects.
- Персистентное состояние в **RocksDB**.

### CLI / REPL
```bash
cargo run
```
После запуска открывается постоянная интерактивная консоль (`om-chain>`), она не закрывается командами `exit/quit` и завершается только принудительно (Ctrl+C/закрытие окна).

Команды:
```text
help
show-state
wallet new <name>
wallet import-mnemonic <name> <mnemonic words...>
wallet import-secret <name> <master_secret_hex_64>
wallet export <name>
wallet list
wallet show <name>
balance <wallet:<name>|address_hex>
send <from_wallet> <to_address_hex> <amount>
spectator <object_address_hex>
genesis show
```

### Структура
- `src/core` — модели состояния, tx, state executor.
- `src/crypto` — подписи, генератор OTK, Merkle proof membership.
- `src/object_standards` — token standard (`BasicToken`, `Coin`).

### Дисклеймер
Проект учебный, не production-ready. Перед реальным запуском нужны аудит, threat modeling, p2p/consensus, продуманный key lifecycle, telemetry и расширенное тестирование.

---

## English

### Project concept
This is an educational object-model blockchain runtime:
- state is stored as objects and coin objects,
- transactions carry `effects`,
- authorization is enforced in state execution,
- signing uses **one-time keys (OTK)** without exposing master public key in transactions.

### One-time key security model
1. An account owns a pool of one-time keys.
2. Their public keys are committed into a Merkle tree.
3. Only `one_time_root` is registered in on-chain state.
4. A transaction includes:
   - `one_time_public_key`,
   - `one_time_index`,
   - `one_time_merkle_proof`,
   - signature by that one-time key.
5. The node verifies:
   - signature validity,
   - Merkle membership against account root,
   - one-time index has not been used before,
   - nonce,
   - ownership checks for each effect.

This ensures: **master public key is never exposed in tx payload**.

### Implemented features
- Object model (`Object`, `Coin`, `Owner`, `ObjectAddress`).
- Transaction effects:
  - `TransferObject`
  - `TransferCoin`
  - `RotateOneTimeRoot`
- Domain-separated transaction signing:
  - `TX_INTENT_V1`
  - `chain_id`
  - `tx_version`
- Protections:
  - anti-replay (`nonce`),
  - one-time key reuse prevention,
  - proof length limit,
  - max effects limit.
- Persistent state with **RocksDB**.

### CLI / REPL
```bash
cargo run
```
This starts a persistent interactive console (`om-chain>`). It does not exit via `exit/quit`; stop it with Ctrl+C or by closing the terminal window.

Commands:
```text
help
show-state
wallet new <name>
wallet import-mnemonic <name> <mnemonic words...>
wallet import-secret <name> <master_secret_hex_64>
wallet export <name>
wallet list
wallet show <name>
balance <wallet:<name>|address_hex>
send <from_wallet> <to_address_hex> <amount>
spectator <object_address_hex>
genesis show
```

### Repository layout
- `src/core` — state models, transactions, state executor.
- `src/crypto` — signatures, OTK manager, Merkle membership checks.
- `src/object_standards` — token standard (`BasicToken`, `Coin`).

### Disclaimer
Educational project, not production-ready. A real deployment requires formal security review, threat modeling, p2p/consensus, robust key lifecycle, observability, and extensive testing.
