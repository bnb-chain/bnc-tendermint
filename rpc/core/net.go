package core

import (
	"github.com/pkg/errors"

	"github.com/tendermint/tendermint/p2p"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
)

// Get network info.
//
// ```shell
// curl 'localhost:26657/net_info'
// ```
//
// ```go
// client := client.NewHTTP("tcp://0.0.0.0:26657", "/websocket")
// info, err := client.NetInfo()
// ```
//
// > The above command returns JSON structured like this:
//
// ```json
// {
// 	"error": "",
// 	"result": {
//		"n_peers": 0,
// 		"peers": [],
// 		"listeners": [
// 			"Listener(@10.0.2.15:26656)"
// 		],
// 		"listening": true
// 	},
// 	"id": "",
// 	"jsonrpc": "2.0"
// }
// ```
func NetInfo() (*ctypes.ResultNetInfo, error) {
	peers := []ctypes.Peer{}
	for _, peer := range p2pPeers.Peers().List() {
		peers = append(peers, ctypes.Peer{
			HostPort:         peer.OriginalAddr().DialString(),
			NodeInfo:         peer.NodeInfo(),
			IsOutbound:       peer.IsOutbound(),
			ConnectionStatus: peer.Status(),
		})
	}
	// TODO: Should we include PersistentPeers and Seeds in here?
	// PRO: useful info
	// CON: privacy
	return &ctypes.ResultNetInfo{
		Listening: p2pTransport.IsListening(),
		Listeners: p2pTransport.Listeners(),
		NPeers:    len(peers),
		Peers:     peers,
	}, nil
}

func AddSignedPeers(peers []string, persistent bool) (*ctypes.ResultDialPeers, error) {
	if len(peers) == 0 {
		return &ctypes.ResultDialPeers{}, errors.New("No peers provided")
	}
	// starts go routines to dial each peer after random delays
	logger.Info("AddSignedPeers", "addrBook", addrBook, "peers", peers, "persistent", persistent)
	err := p2pPeers.DialPeersAsync(peers, persistent, true)
	if err != nil {
		return &ctypes.ResultDialPeers{}, err
	}
	return &ctypes.ResultDialPeers{"Dialing peers in progress. See /net_info for details"}, nil
}

// unsafe peers operations

func UnsafeSignPeerAddr(peer string) (*ctypes.ResultSignPeer, error) {
	logger.Info("UnsafeSignPeerAddr", "peer", peer)
	if len(peer) == 0 {
		return &ctypes.ResultSignPeer{}, errors.New("No peer provided")
	}
	// try to create a NetAddress out of it. do not read a signature at this point
	addr, err := p2p.NewNetAddressStringWithOptionalID(peer)
	if err != nil {
		return &ctypes.ResultSignPeer{}, err
	}
	addrStr := addr.String()
	signed, err := addrBook.SignPeerString(addrStr)
	if err != nil {
		return &ctypes.ResultSignPeer{}, err
	}
	return &ctypes.ResultSignPeer{
		OriginalAddr: addrStr,
		SignedAddr:   signed.String(),
	}, nil
}

func UnsafeDialPeers(peers []string, persistent bool) (*ctypes.ResultDialPeers, error) {
	if len(peers) == 0 {
		return &ctypes.ResultDialPeers{}, errors.New("No peers provided")
	}
	// starts go routines to dial each peer after random delays
	logger.Info("DialPeers", "addrBook", addrBook, "peers", peers, "persistent", persistent)
	err := p2pPeers.DialPeersAsync(peers, persistent, false)
	if err != nil {
		return &ctypes.ResultDialPeers{}, err
	}
	return &ctypes.ResultDialPeers{"Dialing peers in progress. See /net_info for details"}, nil
}

func UnsafeDialSeeds(seeds []string) (*ctypes.ResultDialSeeds, error) {
	if len(seeds) == 0 {
		return &ctypes.ResultDialSeeds{}, errors.New("No seeds provided")
	}
	// starts go routines to dial each peer after random delays
	logger.Info("DialSeeds", "addrBook", addrBook, "seeds", seeds)
	err := p2pPeers.DialPeersAsync(seeds, false, false)
	if err != nil {
		return &ctypes.ResultDialSeeds{}, err
	}
	return &ctypes.ResultDialSeeds{"Dialing seeds in progress. See /net_info for details"}, nil
}

// / unsafe

// Get genesis file.
//
// ```shell
// curl 'localhost:26657/genesis'
// ```
//
// ```go
// client := client.NewHTTP("tcp://0.0.0.0:26657", "/websocket")
// genesis, err := client.Genesis()
// ```
//
// > The above command returns JSON structured like this:
//
// ```json
// {
// 	"error": "",
// 	"result": {
// 		"genesis": {
// 			"app_hash": "",
// 			"validators": [
// 				{
// 					"name": "",
// 					"power": 10,
// 					"pub_key": {
// 						"data": "68DFDA7E50F82946E7E8546BED37944A422CD1B831E70DF66BA3B8430593944D",
// 						"type": "ed25519"
// 					}
// 				}
// 			],
// 			"chain_id": "test-chain-6UTNIN",
// 			"genesis_time": "2017-05-29T15:05:41.671Z"
// 		}
// 	},
// 	"id": "",
// 	"jsonrpc": "2.0"
// }
// ```
func Genesis() (*ctypes.ResultGenesis, error) {
	return &ctypes.ResultGenesis{genDoc}, nil
}
