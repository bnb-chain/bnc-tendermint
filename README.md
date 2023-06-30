# Tendermint
This repo is forked from [tendermint](https://github.com/tendermint/tendermint). Tendermint Core is Byzantine Fault Tolerant (BFT) middleware that takes a state transition machine - written in any programming language -
and securely replicates it on many machines.

For protocol details, see [the specification](/docs/spec).

## Key Features
We implement several key features based on the Tendermint fork:

1. State Sync. State sync is a way to help newly-joined users sync the latest status of the BNB Chain. It syncs the latest sync-able peer's status so that fullnode user (who wants to catch up with chain as soon as possible with a cost that discards all historical blocks locally) doesn't need sync from block height 0. Refer to [BEP18](https://github.com/bnb-chain/BEPs/blob/master/BEP18.md) for more details.
2. Hot Sync. A new block sync protocol to reduce network and CPU resources for full node. Refer to this [PR](https://github.com/bnb-chain/bnc-tendermint/pull/97) for more details.
3. Capacity improvement. Parallelization, dedicated cache, priority lock and many other program skills are applied to improvement the capacity of BNB Beacon Chain.

## Security

To report a security vulnerability, see our [bug bounty
program](https://www.binance.com/hi/support/announcement/360024789131)

For examples of the kinds of bugs we're looking for, see [SECURITY.md](SECURITY.md)

## Minimum requirements

| Requirement | Notes              |
| ----------- | ------------------ |
| Go version  | Go1.11.4 or higher |

### Install

See the [install instructions](/docs/introduction/install.md)

### Quick Start

- [Single node](/docs/introduction/quick-start.md)
- [Join the BNB Beacon Chain Mainnet](https://docs.bnbchain.org/docs/beaconchain/develop/node/join-mainnet)
- [Join the BNB Beacon Chain Testet](https://docs.bnbchain.org/docs/beaconchain/develop/node/join-testnet)

## Contributing

Please abide by the [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions,
and the [contributing guidelines](CONTRIBUTING.md) when submitting code.

To learn more about the structure of the software, watch the [Developer
Sessions](https://www.youtube.com/playlist?list=PLdQIb0qr3pnBbG5ZG-0gr3zM86_s8Rpqv)
and read some [Architectural
Decision Records](https://github.com/bnb-chain/bnc-tendermint/tree/master/docs/architecture).

Learn more by reading the code and comparing it to the
[specification](https://github.com/bnb-chain/bnc-tendermint/tree/develop/docs/spec).


## Resources

### Tendermint Core

For details about the blockchain data structures and the p2p protocols, see the
[Tendermint specification](/docs/spec).

For details on using the software, see the [documentation](/docs/) which is also
hosted at: https://tendermint.com/docs/

### Tools

Benchmarking and monitoring is provided by `tm-bench` and `tm-monitor`, respectively.
Their code is found [here](/tools) and these binaries need to be built seperately.
Additional documentation is found [here](/docs/tools).

### Sub-projects

- [Amino](http://github.com/tendermint/go-amino), reflection-based proto3, with interfaces
- [IAVL](http://github.com/tendermint/iavl), Merkleized IAVL+ Tree implementation
