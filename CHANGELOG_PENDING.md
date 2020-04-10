## develop

\*\*

Special thanks to external contributors on this release:

Friendly reminder, we have a [bug bounty
program](https://hackerone.com/tendermint).

### BREAKING CHANGES:

### FEATURES:

### IMPROVEMENTS:

### BUG FIXES:

### SECURITY
- [p2p] [\#129](https://github.com/binance-chain/bnc-tendermint/pull/137) cherry pick the patch of tendermint [v0.33.3](https://github.com/tendermint/tendermint/releases/tag/v0.33.3) to fix the following issues:
#### Denial of service 1

Tendermint 0.33.2 and earlier does not limit P2P connection requests number.
For each p2p connection, Tendermint allocates ~0.5MB. Even though this
memory is garbage collected once the connection is terminated (due to duplicate
IP or reaching a maximum number of inbound peers), temporary memory spikes can
lead to OOM (Out-Of-Memory) exceptions.

Tendermint 0.33.3 (and 0.32.10) limits the total number of P2P incoming
connection requests to to `p2p.max_num_inbound_peers +
len(p2p.unconditional_peer_ids)`.

### Denial of service 2

Tendermint 0.33.2 and earlier does not reclaim `activeID` of a peer after it's
removed in `Mempool` reactor. This does not happen all the time. It only
happens when a connection fails (for any reason) before the Peer is created and
added to all reactors. `RemovePeer` is therefore called before `AddPeer`, which
leads to always growing memory (`activeIDs` map). The `activeIDs` map has a
maximum size of 65535 and the node will panic if this map reaches the maximum.
An attacker can create a lot of connection attempts (exploiting Denial of
service 1), which ultimately will lead to the node panicking.

Tendermint 0.33.3 (and 0.32.10) claims `activeID` for a peer in `InitPeer`,
which is executed before `MConnection` is started.

