package mempool

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	amino "github.com/tendermint/go-amino"
	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	auto "github.com/tendermint/tendermint/libs/autofile"
	"github.com/tendermint/tendermint/libs/clist"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/proxy"
	"github.com/tendermint/tendermint/types"
)

// PreCheckFunc is an optional filter executed before CheckTx and rejects
// transaction if false is returned. An example would be to ensure that a
// transaction doesn't exceeded the block size.
type PreCheckFunc func(types.Tx) bool

// PostCheckFunc is an optional filter executed after CheckTx and rejects
// transaction if false is returned. An example would be to ensure a
// transaction doesn't require more gas than available for the block.
type PostCheckFunc func(types.Tx, *abci.ResponseCheckTx) bool

/*

The mempool pushes new txs onto the proxyAppConn.
It gets a stream of (req, res) tuples from the proxy.
The mempool stores good txs in a concurrent linked-list.

Multiple concurrent go-routines can traverse this linked-list
safely by calling .NextWait() on each element.

So we have several go-routines:
1. Consensus calling Update() and Reap() synchronously
2. Many mempool reactor's peer routines calling CheckTx()
3. Many mempool reactor's peer routines traversing the txs linked list
4. Another goroutine calling GarbageCollectTxs() periodically

To manage these goroutines, there are three methods of locking.
1. Mutations to the linked-list is protected by an internal mtx (CList is goroutine-safe)
2. Mutations to the linked-list elements are atomic
3. CheckTx() calls can be paused upon Update() and Reap(), protected by .proxyMtx

Garbage collection of old elements from mempool.txs is handlde via
the DetachPrev() call, which makes old elements not reachable by
peer broadcastTxRoutine() automatically garbage collected.

TODO: Better handle abci client errors. (make it automatically handle connection errors)

*/

var (
	// ErrTxInCache is returned to the client if we saw tx earlier
	ErrTxInCache = errors.New("Tx already exists in cache")

	// ErrMempoolIsFull means Tendermint & an application can't handle that much load
	ErrMempoolIsFull = errors.New("Mempool is full")
)

// PreCheckAminoMaxBytes checks that the size of the transaction plus the amino
// overhead is smaller or equal to the expected maxBytes.
func PreCheckAminoMaxBytes(maxBytes int64) PreCheckFunc {
	return func(tx types.Tx) bool {
		// We have to account for the amino overhead in the tx size as well
		aminoOverhead := amino.UvarintSize(uint64(len(tx)))
		return int64(len(tx)+aminoOverhead) <= maxBytes
	}
}

// PostCheckMaxGas checks that the wanted gas is smaller or equal to the passed
// maxGas. Returns true if maxGas is -1.
func PostCheckMaxGas(maxGas int64) PostCheckFunc {
	return func(tx types.Tx, res *abci.ResponseCheckTx) bool {
		if maxGas == -1 {
			return true
		}
		return res.GasWanted <= maxGas
	}
}

// TxID is the hex encoded hash of the bytes as a types.Tx.
func TxID(tx []byte) string {
	return fmt.Sprintf("%X", types.Tx(tx).Hash())
}

// Mempool is an ordered in-memory pool for transactions before they are proposed in a consensus
// round. Transaction validity is checked using the CheckTx abci message before the transaction is
// added to the pool. The Mempool uses a concurrent list structure for storing transactions that
// can be efficiently accessed by multiple concurrent readers.
type Mempool struct {
	config *cfg.MempoolConfig

	proxyLowMtx          sync.Mutex
	proxyNextMtx         sync.Mutex
	proxyBlockingMtx     sync.Mutex
	proxyAppConn         proxy.AppConnMempool
	txs                  *clist.CList    // concurrent linked-list of good txs
	counter              int64           // simple incrementing counter
	height               int64           // the last block Update()'d to
	rechecking           int32           // for re-checking filtered txs on Update()
	recheckCursor        *clist.CElement // next expected response
	recheckEnd           *clist.CElement // re-checking stops here
	notifiedTxsAvailable bool
	txsAvailable         chan struct{} // fires once for each height, when the mempool is not empty
	preCheck             PreCheckFunc
	postCheck            PostCheckFunc

	// Keep a cache of already-seen txs.
	// This reduces the pressure on the proxyApp.
	cache txCache

	// A log of mempool txs
	wal *auto.AutoFile

	logger log.Logger

	metrics *Metrics
}

// MempoolOption sets an optional parameter on the Mempool.
type MempoolOption func(*Mempool)

// NewMempool returns a new Mempool with the given configuration and connection to an application.
func NewMempool(
	config *cfg.MempoolConfig,
	proxyAppConn proxy.AppConnMempool,
	height int64,
	options ...MempoolOption,
) *Mempool {
	mempool := &Mempool{
		config:        config,
		proxyAppConn:  proxyAppConn,
		txs:           clist.New(),
		counter:       0,
		height:        height,
		rechecking:    0,
		recheckCursor: nil,
		recheckEnd:    nil,
		logger:        log.NewNopLogger(),
		metrics:       NopMetrics(),
	}
	if config.CacheSize > 0 {
		mempool.cache = newMapTxCache(config.CacheSize)
	} else {
		mempool.cache = nopTxCache{}
	}
	proxyAppConn.SetResponseCallback(mempool.resCb)
	for _, option := range options {
		option(mempool)
	}
	return mempool
}

// EnableTxsAvailable initializes the TxsAvailable channel,
// ensuring it will trigger once every height when transactions are available.
// NOTE: not thread safe - should only be called once, on startup
func (mem *Mempool) EnableTxsAvailable() {
	mem.txsAvailable = make(chan struct{}, 1)
}

// SetLogger sets the Logger.
func (mem *Mempool) SetLogger(l log.Logger) {
	mem.logger = l
}

// WithPreCheck sets a filter for the mempool to reject a tx if f(tx) returns
// false. This is ran before CheckTx.
func WithPreCheck(f PreCheckFunc) MempoolOption {
	return func(mem *Mempool) { mem.preCheck = f }
}

// WithPostCheck sets a filter for the mempool to reject a tx if f(tx) returns
// false. This is ran after CheckTx.
func WithPostCheck(f PostCheckFunc) MempoolOption {
	return func(mem *Mempool) { mem.postCheck = f }
}

// WithMetrics sets the metrics.
func WithMetrics(metrics *Metrics) MempoolOption {
	return func(mem *Mempool) { mem.metrics = metrics }
}

// CloseWAL closes and discards the underlying WAL file.
// Any further writes will not be relayed to disk.
func (mem *Mempool) CloseWAL() bool {
	if mem == nil {
		return false
	}

	mem.Lock()
	defer mem.Unlock()

	if mem.wal == nil {
		return false
	}
	if err := mem.wal.Close(); err != nil && mem.logger != nil {
		mem.logger.Error("Mempool.CloseWAL", "err", err)
	}
	mem.wal = nil
	return true
}

func (mem *Mempool) InitWAL() {
	walDir := mem.config.WalDir()
	if walDir != "" {
		err := cmn.EnsureDir(walDir, 0700)
		if err != nil {
			cmn.PanicSanity(errors.Wrap(err, "Error ensuring Mempool wal dir"))
		}
		af, err := auto.OpenAutoFile(walDir + "/wal")
		if err != nil {
			cmn.PanicSanity(errors.Wrap(err, "Error opening Mempool wal file"))
		}
		mem.wal = af
	}
}

// Lock locks the mempool. The consensus must be able to hold lock to safely update.
func (mem *Mempool) Lock() {
	mem.proxyNextMtx.Lock()
	mem.proxyBlockingMtx.Lock()
	mem.proxyNextMtx.Unlock()
}

// Unlock unlocks the mempool.
func (mem *Mempool) Unlock() {
	mem.proxyBlockingMtx.Unlock()
}

//LockLow uses triple mutex to low the priority of CheckTx()
func (mem *Mempool) LockLow() {
	mem.proxyLowMtx.Lock()
	mem.proxyNextMtx.Lock()
	mem.proxyBlockingMtx.Lock()
	mem.proxyNextMtx.Unlock()
}

func (mem *Mempool) UnlockLow() {
	mem.proxyBlockingMtx.Unlock()
	mem.proxyLowMtx.Unlock()
}

// Size returns the number of transactions in the mempool.
func (mem *Mempool) Size() int {
	return mem.txs.Len()
}

// Flushes the mempool connection to ensure async resCb calls are done e.g.
// from CheckTx.
func (mem *Mempool) FlushAppConn() error {
	return mem.proxyAppConn.FlushSync()
}

// Flush removes all transactions from the mempool and cache
func (mem *Mempool) Flush() {
	mem.Lock()
	defer mem.Unlock()

	mem.cache.Reset()

	for e := mem.txs.Front(); e != nil; e = e.Next() {
		mem.txs.Remove(e)
		e.DetachPrev()
	}
}

// TxsFront returns the first transaction in the ordered list for peer
// goroutines to call .NextWait() on.
func (mem *Mempool) TxsFront() *clist.CElement {
	return mem.txs.Front()
}

// TxsWaitChan returns a channel to wait on transactions. It will be closed
// once the mempool is not empty (ie. the internal `mem.txs` has at least one
// element)
func (mem *Mempool) TxsWaitChan() <-chan struct{} {
	return mem.txs.WaitChan()
}

// CheckTx executes a new transaction against the application to determine its validity
// and whether it should be added to the mempool.
// It blocks if we're waiting on Update() or Reap().
// cb: A callback from the CheckTx command.
//     It gets called from another goroutine.
// CONTRACT: Either cb will get called, or err returned.
func (mem *Mempool) CheckTx(tx types.Tx, cb func(*abci.Response)) (err error) {
	mem.LockLow()
	defer mem.UnlockLow()

	if mem.Size() >= mem.config.Size {
		return ErrMempoolIsFull
	}

	if mem.preCheck != nil && !mem.preCheck(tx) {
		return
	}

	// CACHE
	if !mem.cache.Push(tx) {
		return ErrTxInCache
	}
	// END CACHE

	// WAL
	if mem.wal != nil {
		// TODO: Notify administrators when WAL fails
		_, err := mem.wal.Write([]byte(tx))
		if err != nil {
			mem.logger.Error("Error writing to WAL", "err", err)
		}
		_, err = mem.wal.Write([]byte("\n"))
		if err != nil {
			mem.logger.Error("Error writing to WAL", "err", err)
		}
	}
	// END WAL

	// NOTE: proxyAppConn may error if tx buffer is full
	if err = mem.proxyAppConn.Error(); err != nil {
		return err
	}
	reqRes := mem.proxyAppConn.CheckTxAsync(tx)
	if cb != nil {
		reqRes.SetCallback(cb)
	}

	return nil
}

func(mem *Mempool) SimulateTx(tx types.Tx) (*abci.ResponseCheckTx, error) {
	return mem.proxyAppConn.SimulateTxSync(tx)
}

// ABCI callback function
func (mem *Mempool) resCb(req *abci.Request, res *abci.Response) {
	if mem.recheckCursor == nil {
		mem.resCbNormal(req, res)
	} else {
		mem.resCbRecheck(req, res)
	}
	mem.metrics.Size.Set(float64(mem.Size()))
}

func (mem *Mempool) resCbNormal(req *abci.Request, res *abci.Response) {
	switch r := res.Value.(type) {
	case *abci.Response_CheckTx:
		tx := req.GetCheckTx().Tx
		if (r.CheckTx.Code == abci.CodeTypeOK) &&
			mem.isPostCheckPass(tx, r.CheckTx) {
			mem.counter++
			memTx := &mempoolTx{
				counter:   mem.counter,
				height:    mem.height,
				gasWanted: r.CheckTx.GasWanted,
				tx:        tx,
			}
			mem.txs.PushBack(memTx)
			mem.logger.Info("Added good transaction", "tx", TxID(tx), "res", r, "total", mem.Size())
			mem.notifyTxsAvailable()
		} else {
			// ignore bad transaction
			mem.logger.Info("Rejected bad transaction", "tx", TxID(tx), "res", r)

			// remove from cache (it might be good later)
			mem.cache.Remove(tx)
		}
	default:
		// ignore other messages
	}
}

func (mem *Mempool) resCbRecheck(req *abci.Request, res *abci.Response) {
	switch r := res.Value.(type) {
	case *abci.Response_CheckTx:
		memTx := mem.recheckCursor.Value.(*mempoolTx)
		if !bytes.Equal(req.GetCheckTx().Tx, memTx.tx) {
			cmn.PanicSanity(
				fmt.Sprintf(
					"Unexpected tx response from proxy during recheck\nExpected %X, got %X",
					r.CheckTx.Data,
					memTx.tx,
				),
			)
		}
		if (r.CheckTx.Code == abci.CodeTypeOK) && mem.isPostCheckPass(memTx.tx, r.CheckTx) {
			// Good, nothing to do.
		} else {
			// Tx became invalidated due to newly committed block.
			mem.txs.Remove(mem.recheckCursor)
			mem.recheckCursor.DetachPrev()

			// remove from cache (it might be good later)
			mem.cache.Remove(req.GetCheckTx().Tx)
		}
		if mem.recheckCursor == mem.recheckEnd {
			mem.recheckCursor = nil
		} else {
			mem.recheckCursor = mem.recheckCursor.Next()
		}
		if mem.recheckCursor == nil {
			// Done!
			atomic.StoreInt32(&mem.rechecking, 0)
			mem.logger.Info("Done rechecking txs")

			// incase the recheck removed all txs
			if mem.Size() > 0 {
				mem.notifyTxsAvailable()
			}
		}
	default:
		// ignore other messages
	}
}

// TxsAvailable returns a channel which fires once for every height,
// and only when transactions are available in the mempool.
// NOTE: the returned channel may be nil if EnableTxsAvailable was not called.
func (mem *Mempool) TxsAvailable() <-chan struct{} {
	return mem.txsAvailable
}

func (mem *Mempool) notifyTxsAvailable() {
	if mem.Size() == 0 {
		panic("notified txs available but mempool is empty!")
	}
	if mem.txsAvailable != nil && !mem.notifiedTxsAvailable {
		// channel cap is 1, so this will send once
		mem.notifiedTxsAvailable = true
		select {
		case mem.txsAvailable <- struct{}{}:
		default:
		}
	}
}

// ReapMaxBytesMaxGas reaps transactions from the mempool up to maxBytes bytes total
// with the condition that the total gasWanted must be less than maxGas.
// If both maxes are negative, there is no cap on the size of all returned
// transactions (~ all available transactions).
func (mem *Mempool) ReapMaxBytesMaxGas(maxBytes, maxGas int64) types.Txs {
	mem.Lock()
	defer mem.Unlock()

	for atomic.LoadInt32(&mem.rechecking) > 0 {
		// TODO: Something better?
		time.Sleep(time.Millisecond * 10)
	}

	var totalBytes int64
	var totalGas int64
	// TODO: we will get a performance boost if we have a good estimate of avg
	// size per tx, and set the initial capacity based off of that.
	// txs := make([]types.Tx, 0, cmn.MinInt(mem.txs.Len(), max/mem.avgTxSize))
	txs := make([]types.Tx, 0, mem.txs.Len())
	for e := mem.txs.Front(); e != nil; e = e.Next() {
		memTx := e.Value.(*mempoolTx)
		// Check total size requirement
		// TODO: merge tendermint
		aminoOverhead := int64(amino.UvarintSize(uint64(len(memTx.tx)))) + 1
		if maxBytes > -1 && totalBytes+int64(len(memTx.tx))+aminoOverhead > maxBytes {
			return txs
		}
		totalBytes += int64(len(memTx.tx)) + aminoOverhead
		// Check total gas requirement
		if maxGas > -1 && totalGas+memTx.gasWanted > maxGas {
			return txs
		}
		totalGas += memTx.gasWanted
		txs = append(txs, memTx.tx)
	}
	return txs
}

// ReapMaxTxs reaps up to max transactions from the mempool.
// If max is negative, there is no cap on the size of all returned
// transactions (~ all available transactions).
func (mem *Mempool) ReapMaxTxs(max int) types.Txs {
	mem.Lock()
	defer mem.Unlock()

	if max < 0 {
		max = mem.txs.Len()
	}

	for atomic.LoadInt32(&mem.rechecking) > 0 {
		// TODO: Something better?
		time.Sleep(time.Millisecond * 10)
	}

	txs := make([]types.Tx, 0, cmn.MinInt(mem.txs.Len(), max))
	for e := mem.txs.Front(); e != nil && len(txs) <= max; e = e.Next() {
		memTx := e.Value.(*mempoolTx)
		txs = append(txs, memTx.tx)
	}
	return txs
}

// Update informs the mempool that the given txs were committed and can be discarded.
// NOTE: this should be called *after* block is committed by consensus.
// NOTE: unsafe; Lock/Unlock must be managed by caller
func (mem *Mempool) Update(
	height int64,
	txs types.Txs,
	preCheck PreCheckFunc,
	postCheck PostCheckFunc,
) error {
	// First, create a lookup map of txns in new txs.
	txsMap := make(map[string]struct{}, len(txs))
	for _, tx := range txs {
		txsMap[string(tx)] = struct{}{}
	}

	// Set height
	mem.height = height
	mem.notifiedTxsAvailable = false

	if preCheck != nil {
		mem.preCheck = preCheck
	}
	if postCheck != nil {
		mem.postCheck = postCheck
	}

	// Remove transactions that are already in txs.
	goodTxs := mem.filterTxs(txsMap)
	// Recheck mempool txs if any txs were committed in the block
	// NOTE/XXX: in some apps a tx could be invalidated due to EndBlock,
	//	so we really still do need to recheck, but this is for debugging
	if mem.config.Recheck && (mem.config.RecheckEmpty || len(goodTxs) > 0) {
		mem.logger.Info("Recheck txs", "numtxs", len(goodTxs), "height", height)
		mem.recheckTxs(goodTxs)
		// At this point, mem.txs are being rechecked.
		// mem.recheckCursor re-scans mem.txs and possibly removes some txs.
		// Before mem.Reap(), we should wait for mem.recheckCursor to be nil.
	}

	// Update metrics
	mem.metrics.Size.Set(float64(mem.Size()))

	return nil
}

func (mem *Mempool) filterTxs(blockTxsMap map[string]struct{}) []types.Tx {
	goodTxs := make([]types.Tx, 0, mem.txs.Len())
	for e := mem.txs.Front(); e != nil; e = e.Next() {
		memTx := e.Value.(*mempoolTx)
		// Remove the tx if it's alredy in a block.
		if _, ok := blockTxsMap[string(memTx.tx)]; ok {
			// remove from clist
			mem.txs.Remove(e)
			e.DetachPrev()

			// NOTE: we don't remove committed txs from the cache.
			continue
		}
		// Good tx!
		goodTxs = append(goodTxs, memTx.tx)
	}
	return goodTxs
}

// NOTE: pass in goodTxs because mem.txs can mutate concurrently.
func (mem *Mempool) recheckTxs(goodTxs []types.Tx) {
	if len(goodTxs) == 0 {
		return
	}
	atomic.StoreInt32(&mem.rechecking, 1)
	mem.recheckCursor = mem.txs.Front()
	mem.recheckEnd = mem.txs.Back()

	// Push txs to proxyAppConn
	// NOTE: resCb() may be called concurrently.
	for _, tx := range goodTxs {
		mem.proxyAppConn.ReCheckTxAsync(tx)
	}
	mem.proxyAppConn.FlushAsync()
}

func (mem *Mempool) isPostCheckPass(tx types.Tx, r *abci.ResponseCheckTx) bool {
	return mem.postCheck == nil || mem.postCheck(tx, r)
}

//--------------------------------------------------------------------------------

// mempoolTx is a transaction that successfully ran
type mempoolTx struct {
	counter   int64    // a simple incrementing counter
	height    int64    // height that this tx had been validated in
	gasWanted int64    // amount of gas this tx states it will require
	tx        types.Tx //
}

// Height returns the height for this transaction
func (memTx *mempoolTx) Height() int64 {
	return atomic.LoadInt64(&memTx.height)
}

//--------------------------------------------------------------------------------

type txCache interface {
	Reset()
	Push(tx types.Tx) bool
	Remove(tx types.Tx)
}

// mapTxCache maintains a cache of transactions. This only stores
// the hash of the tx, due to memory concerns.
type mapTxCache struct {
	mtx  sync.Mutex
	size int
	map_ map[[sha256.Size]byte]*list.Element
	list *list.List // to remove oldest tx when cache gets too big
}

var _ txCache = (*mapTxCache)(nil)

// newMapTxCache returns a new mapTxCache.
func newMapTxCache(cacheSize int) *mapTxCache {
	return &mapTxCache{
		size: cacheSize,
		map_: make(map[[sha256.Size]byte]*list.Element, cacheSize),
		list: list.New(),
	}
}

// Reset resets the cache to an empty state.
func (cache *mapTxCache) Reset() {
	cache.mtx.Lock()
	cache.map_ = make(map[[sha256.Size]byte]*list.Element, cache.size)
	cache.list.Init()
	cache.mtx.Unlock()
}

// Push adds the given tx to the cache and returns true. It returns false if tx
// is already in the cache.
func (cache *mapTxCache) Push(tx types.Tx) bool {
	cache.mtx.Lock()
	defer cache.mtx.Unlock()

	// Use the tx hash in the cache
	txHash := sha256.Sum256(tx)
	if moved, exists := cache.map_[txHash]; exists {
		cache.list.MoveToFront(moved)
		return false
	}

	if cache.list.Len() >= cache.size {
		popped := cache.list.Front()
		poppedTxHash := popped.Value.([sha256.Size]byte)
		delete(cache.map_, poppedTxHash)
		if popped != nil {
			cache.list.Remove(popped)
		}
	}
	cache.list.PushBack(txHash)
	cache.map_[txHash] = cache.list.Back()
	return true
}

// Remove removes the given tx from the cache.
func (cache *mapTxCache) Remove(tx types.Tx) {
	cache.mtx.Lock()
	txHash := sha256.Sum256(tx)
	popped := cache.map_[txHash]
	delete(cache.map_, txHash)
	if popped != nil {
		cache.list.Remove(popped)
	}

	cache.mtx.Unlock()
}

type nopTxCache struct{}

var _ txCache = (*nopTxCache)(nil)

func (nopTxCache) Reset()             {}
func (nopTxCache) Push(types.Tx) bool { return true }
func (nopTxCache) Remove(types.Tx)    {}
