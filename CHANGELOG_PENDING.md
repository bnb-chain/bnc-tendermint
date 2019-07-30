## v0.32.2

\*\*

Special thanks to external contributors on this release:

Friendly reminder, we have a [bug bounty
program](https://hackerone.com/tendermint).

### BREAKING CHANGES:

- CLI/RPC/Config

- Apps

- Go API

### FEATURES:
- [node] Allow replacing existing p2p.Reactor(s) using [`CustomReactors`
  option](https://godoc.org/github.com/tendermint/tendermint/node#CustomReactors).
  Warning: beware of accidental name clashes. Here is the list of existing
  reactors: MEMPOOL, BLOCKCHAIN, CONSENSUS, EVIDENCE, PEX.

### IMPROVEMENTS:

### BUG FIXES:
