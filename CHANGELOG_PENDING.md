## v0.31.8

**

### BREAKING CHANGES:

- \#3613 Switch from golang/dep to Go 1.11 Modules to resolve dependencies:
  - it is recommended to switch to Go Modules if your project has tendermint 
  as a dependency
  - read more on Modules here: https://github.com/golang/go/wiki/Modules  

* CLI/RPC/Config
- [rpc] \#3616 Improve `/block_results` response format (`results.DeliverTx` ->
  `results.deliver_tx`). See docs for details.

* Apps

* Go API
- [libs/db] Removed deprecated `LevelDBBackend` const
  * If you have `db_backend` set to `leveldb` in your config file, please
    change it to `goleveldb` or `cleveldb`.
- [p2p] \#3521 Remove NewNetAddressStringWithOptionalID
- [abci] \#3193 Use RequestDeliverTx and RequestCheckTx in the ABCI interface

* Blockchain Protocol

* P2P Protocol

### FEATURES:

### IMPROVEMENTS:
- [p2p] \#3666 Add per channel telemetry to improve reactor observability
- [rpc] [\#3686](https://github.com/tendermint/tendermint/pull/3686) `HTTPClient#Call` returns wrapped errors, so a caller could use `errors.Cause` to retrieve an error code. (@wooparadog)
- [abci/examples] \#3659 Change validator update tx format (incl. expected pubkey format, which is base64 now) (@needkane)

### BUG FIXES:
- [libs/db] \#3717 Fixed the BoltDB backend's Batch.Delete implementation (@Yawning)
- [libs/db] \#3718 Fixed the BoltDB backend's Get and Iterator implementation (@Yawning)
- [node] \#3716 Fix a bug where `nil` is recorded as node's address
