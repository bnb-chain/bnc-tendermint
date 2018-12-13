package blockchain

import (
	"fmt"
	"github.com/tendermint/tendermint/proxy"
	"reflect"
	"time"

	"github.com/tendermint/go-amino"

	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/p2p"
	sm "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"
)

/*
	XXX: This file is copied from blockchain/reactor.go
*/

const (
	// BlockchainStateChannel is a channel for state and status updates (`StateStore` height)
	BlockchainStateChannel = byte(0x35)

	tryStateSyncIntervalMS = 10

	// stop syncing when last block's time is
	// within this much of the system time.
	// stopSyncingDurationMinutes = 10

	// ask for best height every 10s
	stateStatusUpdateIntervalSeconds = 10
	// check if we should switch to blockchain reactor
	switchToFastSyncIntervalSeconds = 1

	// NOTE: keep up to date with bcBlockResponseMessage
	bcStateResponseMessagePrefixSize   = 4
	bcStateResponseMessageFieldKeySize = 1
	maxStateMsgSize                    = types.MaxStateSizeBytes +
		bcStateResponseMessagePrefixSize +
		bcStateResponseMessageFieldKeySize
)

// BlockchainReactor handles long-term catchup syncing.
type StateReactor struct {
	p2p.BaseReactor

	// immutable
	initialState sm.State

	stateDB           dbm.DB
	app               proxy.AppConnState
	pool              *StatePool
	fastestSyncHeight int64 // positive for enable this reactor

	requestsCh <-chan StateRequest
	errorsCh   <-chan peerError
}

// NewBlockchainReactor returns new reactor instance.
func NewStateReactor(state sm.State, stateDB dbm.DB, app proxy.AppConnState, fastestSyncHeight int64) *StateReactor {

	// TODO: revisit doesn't need
	//if state.LastBlockHeight != store.Height() {
	//	panic(fmt.Sprintf("state (%v) and store (%v) height mismatch", state.LastBlockHeight,
	//		store.Height()))
	//}

	requestsCh := make(chan StateRequest, maxTotalRequesters)

	const capacity = 1000                      // must be bigger than peers count
	errorsCh := make(chan peerError, capacity) // so we don't block in #Receive#pool.AddBlock

	pool := NewStatePool(
		fastestSyncHeight,
		requestsCh,
		errorsCh,
	)

	bcSR := &StateReactor{
		initialState:      state,
		stateDB:           stateDB,
		app:               app,
		pool:              pool,
		fastestSyncHeight: fastestSyncHeight,
		requestsCh:        requestsCh,
		errorsCh:          errorsCh,
	}
	bcSR.BaseReactor = *p2p.NewBaseReactor("BlockchainStateReactor", bcSR)
	return bcSR
}

// SetLogger implements cmn.Service by setting the logger on reactor and pool.
func (bcSR *StateReactor) SetLogger(l log.Logger) {
	bcSR.BaseService.Logger = l
	bcSR.pool.Logger = l
}

// OnStart implements cmn.Service.
func (bcSR *StateReactor) OnStart() error {
	if bcSR.fastestSyncHeight > 0 {
		err := bcSR.pool.Start()
		if err != nil {
			return err
		}
		go bcSR.poolRoutine()
	}
	return nil
}

// OnStop implements cmn.Service.
func (bcSR *StateReactor) OnStop() {
	bcSR.pool.Stop()
}

// GetChannels implements Reactor
func (_ *StateReactor) GetChannels() []*p2p.ChannelDescriptor {
	return []*p2p.ChannelDescriptor{
		{
			ID:                  BlockchainStateChannel,
			Priority:            10,
			SendQueueCapacity:   1000,
			RecvBufferCapacity:  50 * 4096,
			RecvMessageCapacity: maxStateMsgSize,
		},
	}
}

// AddPeer implements Reactor by sending our state to peer.
func (bcSR *StateReactor) AddPeer(peer p2p.Peer) {
	// TODO: revisit whether to keep
	_, numKeys, _ := bcSR.app.LatestSnapshot()
	keys := make([]keysPerStore, len(numKeys), len(numKeys))
	for storeName, num := range numKeys {
		keys = append(keys, keysPerStore{storeName, num})
	}
	msgBytes := cdc.MustMarshalBinaryBare(&bcStateStatusResponseMessage{sm.LoadState(bcSR.stateDB).LastBlockHeight, keys})
	if !peer.Send(BlockchainStateChannel, msgBytes) {
		// doing nothing, will try later in `poolRoutine`
	}
	// peer is added to the pool once we receive the first
	// bcStateStatusResponseMessage from the peer and call pool.SetPeerHeight
}

// RemovePeer implements Reactor by removing peer from the pool.
func (bcSR *StateReactor) RemovePeer(peer p2p.Peer, reason interface{}) {
	bcSR.pool.RemovePeer(peer.ID())
}

// respondToPeer loads a state and sends it to the requesting peer,
// if we have it. Otherwise, we'll respond saying we don't have it.
// According to the Tendermint spec, if all nodes are honest,
// no node should be requesting for a state that's non-existent.
func (bcSR *StateReactor) respondToPeer(msg *bcStateRequestMessage,
	src p2p.Peer) (queued bool) {

	state := sm.LoadStateForHeight(bcSR.stateDB, msg.Height)
	if state == nil {
		bcSR.Logger.Info("Peer asking for a state we don't have", "src", src, "height", msg.Height)

		msgBytes := cdc.MustMarshalBinaryBare(&bcNoStateResponseMessage{Height: msg.Height})
		return src.TrySend(BlockchainStateChannel, msgBytes)
	}

	appState, err := bcSR.app.ReadSnapshotChunk(msg.Height, 0, 0)
	if err != nil {
		bcSR.Logger.Info("Peer asking for an application state we don't have", "src", src, "height", msg.Height, "err", err)

		msgBytes := cdc.MustMarshalBinaryBare(&bcNoStateResponseMessage{Height: msg.Height})
		return src.TrySend(BlockchainStateChannel, msgBytes)
	}

	serializedStores := make([]serializedStore, 0, len(appState))
	for storeName, keyValues := range appState {
		serializedStores = append(serializedStores, serializedStore{storeName, keyValues})
	}
	fmt.Printf("state lastheight: %d, apphash: %X\n", state.LastBlockHeight, state.AppHash)
	msgBytes := cdc.MustMarshalBinaryBare(&bcStateResponseMessage{State: state, AppState: serializedStores})
	return src.TrySend(BlockchainStateChannel, msgBytes)

}

// Receive implements Reactor by handling 4 types of messages (look below).
func (bcSR *StateReactor) Receive(chID byte, src p2p.Peer, msgBytes []byte) {
	msg, err := decodeStateMsg(msgBytes)
	if err != nil {
		bcSR.Logger.Error("Error decoding message", "src", src, "chId", chID, "msg", msg, "err", err, "bytes", msgBytes)
		bcSR.Switch.StopPeerForError(src, err)
		return
	}

	bcSR.Logger.Debug("Receive", "src", src, "chID", chID, "msg", msg)

	switch msg := msg.(type) {
	case *bcStateRequestMessage:
		if queued := bcSR.respondToPeer(msg, src); !queued {
			// Unfortunately not queued since the queue is full.
		}
	case *bcStateResponseMessage:
		// Got a block.
		//bcSR.pool.AddState(src.ID(), msg.State, len(msgBytes))
		//bcSR.pool.PopRequest()

		sm.SaveState(bcSR.stateDB, *msg.State)
		for _, store := range msg.AppState {
			err := bcSR.app.WriteRecoveryChunk(store.StoreName, store.KeyValues)
			if err != nil {
				bcSR.Logger.Error("Failed to recover application state", "store", store, "numOfKeys", len(store.KeyValues)/2)
			}
		}
		bcSR.app.EndRecovery(msg.State.LastBlockHeight)

		bcSR.Logger.Info("Time to switch to blockchain reactor!", "height", msg.State.LastBlockHeight+1)
		bcSR.pool.Stop()

		bcR := bcSR.Switch.Reactor("BLOCKCHAIN").(*BlockchainReactor)
		bcR.SwitchToBlockchain(*msg.State)
	case *bcStateStatusRequestMessage:
		// Send peer our state.
		height, numKeys, err := bcSR.app.LatestSnapshot()
		if err != nil {
			bcSR.Logger.Error("failed to load application state", "err", err)
		}
		state := sm.LoadState(bcSR.stateDB)
		if state.LastBlockHeight != height {
			bcSR.Logger.Error("application and state height is inconsistent")
		}
		keys := make([]keysPerStore, len(numKeys), len(numKeys))
		for storeName, num := range numKeys {
			keys = append(keys, keysPerStore{storeName, num})
		}
		msgBytes := cdc.MustMarshalBinaryBare(&bcStateStatusResponseMessage{state.LastBlockHeight, keys})
		queued := src.TrySend(BlockchainStateChannel, msgBytes)
		if !queued {
			// sorry
		}
	case *bcStateStatusResponseMessage:
		// Got a peer status. Unverified.
		numKeys := make(map[string]int64)
		for _, keysPerStore := range msg.Keys {
			numKeys[keysPerStore.StoreName] = keysPerStore.NumKeys
		}
		bcSR.app.StartRecovery(msg.Height, numKeys)
		bcSR.pool.SetPeerHeight(src.ID(), msg.Height)
		bcSR.pool.makeRequester(msg.Height)
	default:
		bcSR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
	}
}

// Handle messages from the poolReactor telling the reactor what to do.
// NOTE: Don't sleep in the FOR_LOOP or otherwise slow it down!
func (bcSR *StateReactor) poolRoutine() {

	statusUpdateTicker := time.NewTicker(statusUpdateIntervalSeconds * time.Second)

FOR_LOOP:
	for {
		select {
		case request := <-bcSR.requestsCh:
			peer := bcSR.Switch.Peers().Get(request.PeerID)
			if peer == nil {
				continue FOR_LOOP // Peer has since been disconnected.
			}
			msgBytes := cdc.MustMarshalBinaryBare(&bcStateRequestMessage{request.Height})
			queued := peer.TrySend(BlockchainStateChannel, msgBytes)
			if !queued {
				// We couldn't make the request, send-queue full.
				// The pool handles timeouts, just let it go.
				continue FOR_LOOP
			}

		case err := <-bcSR.errorsCh:
			peer := bcSR.Switch.Peers().Get(err.peerID)
			if peer != nil {
				bcSR.Switch.StopPeerForError(peer, err)
			}

		case <-statusUpdateTicker.C:
			// ask for status updates
			go bcSR.BroadcastStateStatusRequest() // nolint: errcheck

		//case <-switchToBlockTicker.C:
		//	height, numPending, lenRequesters := bcSR.pool.GetStatus()
		//	outbound, inbound, _ := bcSR.Switch.NumPeers()
		//	bcSR.Logger.Debug("Block ticker", "numPending", numPending, "total", lenRequesters,
		//		"outbound", outbound, "inbound", inbound)
		//	if bcSR.pool.IsCaughtUp() {
		//		bcSR.Logger.Info("Time to switch to consensus reactor!", "height", height)
		//		bcSR.pool.Stop()
		//
		//		bcR := bcSR.Switch.Reactor("BLOCKCHAIN").(*BlockchainReactor)
		//		bcR.SwitchToBlockchain(state, blocksSynced)
		//
		//		break FOR_LOOP
		//	}

		case <-bcSR.Quit():
			break FOR_LOOP
		}
	}
}

// BroadcastStatusRequest broadcasts `StateStore` height.
func (bcSR *StateReactor) BroadcastStateStatusRequest() error {
	msgBytes := cdc.MustMarshalBinaryBare(&bcStateStatusRequestMessage{sm.LoadState(bcSR.stateDB).LastBlockHeight})
	bcSR.Switch.Broadcast(BlockchainStateChannel, msgBytes)
	return nil
}

//-----------------------------------------------------------------------------
// Messages

// BlockchainMessage is a generic message for this reactor.
type BlockchainStateMessage interface{}

func RegisterBlockchainStateMessages(cdc *amino.Codec) {
	cdc.RegisterInterface((*BlockchainStateMessage)(nil), nil)
	cdc.RegisterConcrete(&bcStateRequestMessage{}, "tendermint/blockchain/StateRequest", nil)
	cdc.RegisterConcrete(&bcStateResponseMessage{}, "tendermint/blockchain/StateResponse", nil)
	cdc.RegisterConcrete(&bcNoStateResponseMessage{}, "tendermint/blockchain/NoStateResponse", nil)
	cdc.RegisterConcrete(&bcStateStatusResponseMessage{}, "tendermint/blockchain/StateStatusResponse", nil)
	cdc.RegisterConcrete(&bcStateStatusRequestMessage{}, "tendermint/blockchain/StateStatusRequest", nil)
}

func decodeStateMsg(bz []byte) (msg BlockchainStateMessage, err error) {
	if len(bz) > maxMsgSize {
		return msg, fmt.Errorf("State msg exceeds max size (%d > %d)", len(bz), maxMsgSize)
	}
	err = cdc.UnmarshalBinaryBare(bz, &msg)
	return
}

//-------------------------------------

type bcStateRequestMessage struct {
	Height int64
}

func (m *bcStateRequestMessage) String() string {
	return fmt.Sprintf("[bcStateRequestMessage %v]", m.Height)
}

type bcNoStateResponseMessage struct {
	Height int64
}

func (brm *bcNoStateResponseMessage) String() string {
	return fmt.Sprintf("[bcNoStateResponseMessage %d]", brm.Height)
}

//-------------------------------------

type serializedStore struct {
	StoreName string
	KeyValues [][]byte
}

type bcStateResponseMessage struct {
	State    *sm.State
	AppState []serializedStore
}

func (m *bcStateResponseMessage) String() string {
	return fmt.Sprintf("[bcStateResponseMessage %v]", m.State.LastBlockHeight)
}

//-------------------------------------

type bcStateStatusRequestMessage struct {
	Height int64
}

func (m *bcStateStatusRequestMessage) String() string {
	return fmt.Sprintf("[bcStateStatusRequestMessage %v]", m.Height)
}

//-------------------------------------

type keysPerStore struct {
	StoreName string
	NumKeys   int64
}

type bcStateStatusResponseMessage struct {
	Height int64
	Keys   []keysPerStore
}

func (m *bcStateStatusResponseMessage) String() string {
	return fmt.Sprintf("[bcStateStatusResponseMessage %v]", m.Height)
}
