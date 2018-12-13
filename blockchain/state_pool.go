package blockchain

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	cmn "github.com/tendermint/tendermint/libs/common"
	flow "github.com/tendermint/tendermint/libs/flowrate"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/tendermint/tendermint/p2p"
	sm "github.com/tendermint/tendermint/state"
)

/*
	XXX: This file is copied from blockchain/pool.go
*/

/*
	Peers self report their heights when we join the block pool.
	Starting from our latest pool.height, we request blocks
	in sequence from peers that reported higher heights than ours.
	Every so often we ask peers what height they're on so we can keep going.

	Requests are continuously made for blocks of higher heights until
	the limit is reached. If most of the requests have no available peers, and we
	are not at peer limits, we can probably switch to consensus reactor
*/

type StatePool struct {
	cmn.BaseService
	startTime time.Time

	mtx sync.Mutex
	// block requests
	requester *spRequester
	height    int64 // the lowest key in requesters.
	// peers
	peers         map[p2p.ID]*spPeer
	maxPeerHeight int64

	requestsCh chan<- StateRequest
	errorsCh   chan<- peerError
}

func NewStatePool(start int64, requestsCh chan<- StateRequest, errorsCh chan<- peerError) *StatePool {
	sp := &StatePool{
		peers: make(map[p2p.ID]*spPeer),

		height: start,

		requestsCh: requestsCh,
		errorsCh:   errorsCh,
	}
	sp.BaseService = *cmn.NewBaseService(nil, "StatePool", sp)
	return sp
}

func (pool *StatePool) OnStart() error {
	pool.startTime = time.Now()
	return nil
}

func (pool *StatePool) OnStop() {}

func (pool *StatePool) removeTimedoutPeers() {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()

	for _, peer := range pool.peers {
		if !peer.didTimeout && peer.numPending > 0 {
			curRate := peer.recvMonitor.Status().CurRate
			// curRate can be 0 on start
			if curRate != 0 && curRate < minRecvRate {
				err := errors.New("peer is not sending us data fast enough")
				pool.sendError(err, peer.id)
				pool.Logger.Error("SendTimeout", "peer", peer.id,
					"reason", err,
					"curRate", fmt.Sprintf("%d KB/s", curRate/1024),
					"minRate", fmt.Sprintf("%d KB/s", minRecvRate/1024))
				peer.didTimeout = true
			}
		}
		if peer.didTimeout {
			pool.removePeer(peer.id)
		}
	}
}

// TODO: relax conditions, prevent abuse.
func (pool *StatePool) IsCaughtUp() bool {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()

	// Need at least 1 peer to be considered caught up.
	if len(pool.peers) == 0 {
		pool.Logger.Debug("Statepool has no peers")
		return false
	}

	// some conditions to determine if we're caught up
	receivedStateOrTimedOut := (pool.height > 0 || time.Since(pool.startTime) > 5*time.Second)
	ourChainIsLongestAmongPeers := pool.maxPeerHeight == 0 || pool.height >= pool.maxPeerHeight
	isCaughtUp := receivedStateOrTimedOut && ourChainIsLongestAmongPeers
	return isCaughtUp
}

// MaxPeerHeight returns the highest height reported by a peer.
func (pool *StatePool) MaxPeerHeight() int64 {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()
	return pool.maxPeerHeight
}

// Sets the peer's alleged blockchain height.
func (pool *StatePool) SetPeerHeight(peerID p2p.ID, height int64) {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()

	peer := pool.peers[peerID]
	if peer != nil {
		peer.height = height
	} else {
		peer = newSPPeer(pool, peerID, height)
		peer.setLogger(pool.Logger.With("peer", peerID))
		pool.peers[peerID] = peer
	}

	if height > pool.maxPeerHeight {
		pool.maxPeerHeight = height
	}
}

func (pool *StatePool) RemovePeer(peerID p2p.ID) {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()

	pool.removePeer(peerID)
}

func (pool *StatePool) removePeer(peerID p2p.ID) {
	if pool.requester.getPeerID() == peerID {
		pool.requester.redo()
	}
	delete(pool.peers, peerID)
}

// Pick an available peer with at least the given minHeight.
// If no peers are available, returns nil.
func (pool *StatePool) pickIncrAvailablePeer(minHeight int64) *spPeer {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()

	for _, peer := range pool.peers {
		if peer.didTimeout {
			pool.removePeer(peer.id)
			continue
		}
		if peer.numPending >= maxPendingRequestsPerPeer {
			continue
		}
		if peer.height < minHeight {
			continue
		}
		peer.incrPending()
		return peer
	}
	return nil
}

func (pool *StatePool) makeRequester(height int64) {
	pool.mtx.Lock()
	defer pool.mtx.Unlock()

	request := newSPRequester(pool, height)
	// request.SetLogger(pool.Logger.With("height", nextHeight))

	pool.requester = request

	err := request.Start()
	if err != nil {
		request.Logger.Error("Error starting request", "err", err)
	}
}

func (pool *StatePool) sendRequest(height int64, peerID p2p.ID) {
	if !pool.IsRunning() {
		return
	}
	pool.requestsCh <- StateRequest{height, peerID}
}

func (pool *StatePool) sendError(err error, peerID p2p.ID) {
	if !pool.IsRunning() {
		return
	}
	pool.errorsCh <- peerError{err, peerID}
}

//-------------------------------------

type spPeer struct {
	pool        *StatePool
	id          p2p.ID
	recvMonitor *flow.Monitor

	height     int64
	numPending int32
	timeout    *time.Timer
	didTimeout bool

	logger log.Logger
}

func newSPPeer(pool *StatePool, peerID p2p.ID, height int64) *spPeer {
	peer := &spPeer{
		pool:       pool,
		id:         peerID,
		height:     height,
		numPending: 0,
		logger:     log.NewNopLogger(),
	}
	return peer
}

func (peer *spPeer) setLogger(l log.Logger) {
	peer.logger = l
}

func (peer *spPeer) resetMonitor() {
	peer.recvMonitor = flow.New(time.Second, time.Second*40)
	initialValue := float64(minRecvRate) * math.E
	peer.recvMonitor.SetREMA(initialValue)
}

func (peer *spPeer) resetTimeout() {
	if peer.timeout == nil {
		peer.timeout = time.AfterFunc(peerTimeout, peer.onTimeout)
	} else {
		peer.timeout.Reset(peerTimeout)
	}
}

func (peer *spPeer) incrPending() {
	if peer.numPending == 0 {
		peer.resetMonitor()
		peer.resetTimeout()
	}
	peer.numPending++
}

func (peer *spPeer) decrPending(recvSize int) {
	peer.numPending--
	if peer.numPending == 0 {
		peer.timeout.Stop()
	} else {
		peer.recvMonitor.Update(recvSize)
		peer.resetTimeout()
	}
}

func (peer *spPeer) onTimeout() {
	peer.pool.mtx.Lock()
	defer peer.pool.mtx.Unlock()

	err := errors.New("peer did not send us anything")
	peer.pool.sendError(err, peer.id)
	peer.logger.Error("SendTimeout", "reason", err, "timeout", peerTimeout)
	peer.didTimeout = true
}

//-------------------------------------

type spRequester struct {
	cmn.BaseService
	pool       *StatePool
	height     int64
	gotStateCh chan struct{}
	redoCh     chan struct{}

	mtx    sync.Mutex
	peerID p2p.ID
	state  *sm.State
}

func newSPRequester(pool *StatePool, height int64) *spRequester {
	spr := &spRequester{
		pool:       pool,
		height:     height,
		gotStateCh: make(chan struct{}, 1),
		redoCh:     make(chan struct{}, 1),

		peerID: "",
		state:  nil,
	}
	spr.BaseService = *cmn.NewBaseService(nil, "spRequester", spr)
	return spr
}

func (spr *spRequester) OnStart() error {
	go spr.requestRoutine()
	return nil
}

// Returns true if the peer matches and state doesn't already exist.
func (spr *spRequester) setState(state *sm.State, peerID p2p.ID) bool {
	spr.mtx.Lock()
	if spr.state != nil || spr.peerID != peerID {
		spr.mtx.Unlock()
		return false
	}
	spr.state = state
	spr.mtx.Unlock()

	select {
	case spr.gotStateCh <- struct{}{}:
	default:
	}
	return true
}

func (spr *spRequester) getState() *sm.State {
	spr.mtx.Lock()
	defer spr.mtx.Unlock()
	return spr.state
}

func (spr *spRequester) getPeerID() p2p.ID {
	spr.mtx.Lock()
	defer spr.mtx.Unlock()
	return spr.peerID
}

// This is called from the requestRoutine, upon redo().
func (spr *spRequester) reset() {
	spr.mtx.Lock()
	defer spr.mtx.Unlock()

	spr.peerID = ""
	spr.state = nil
}

// Tells spRequester to pick another peer and try again.
// NOTE: Nonblocking, and does nothing if another redo
// was already requested.
func (spr *spRequester) redo() {
	select {
	case spr.redoCh <- struct{}{}:
	default:
	}
}

// Responsible for making more requests as necessary
// Returns only when a state is found (e.g. AddState() is called)
func (spr *spRequester) requestRoutine() {
OUTER_LOOP:
	for {
		// Pick a peer to send request to.
		var peer *spPeer
	PICK_PEER_LOOP:
		for {
			if !spr.IsRunning() || !spr.pool.IsRunning() {
				return
			}
			peer = spr.pool.pickIncrAvailablePeer(spr.height)
			if peer == nil {
				//log.Info("No peers available", "height", height)
				time.Sleep(requestIntervalMS * time.Millisecond)
				continue PICK_PEER_LOOP
			}
			break PICK_PEER_LOOP
		}
		spr.mtx.Lock()
		spr.peerID = peer.id
		spr.mtx.Unlock()

		// Send request and wait.
		spr.pool.sendRequest(spr.height, peer.id)
	WAIT_LOOP:
		for {
			select {
			case <-spr.pool.Quit():
				spr.Stop()
				return
			case <-spr.Quit():
				return
			case <-spr.redoCh:
				spr.reset()
				continue OUTER_LOOP
			case <-spr.gotStateCh:
				// We got a block!
				// Continue the for-loop and wait til Quit.
				continue WAIT_LOOP
			}
		}
	}
}

//-------------------------------------

type StateRequest struct {
	Height int64
	PeerID p2p.ID
}
