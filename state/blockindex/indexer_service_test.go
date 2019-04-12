package blockindex_test

import (
	"encoding/hex"
	"github.com/tendermint/tendermint/state/blockindex"
	kv2 "github.com/tendermint/tendermint/state/blockindex/kv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/types"
)

func genHeader(hashBytes []byte) (*types.Header, cmn.HexBytes) {
	hashHex := make([]byte, 2*len(hashBytes))
	height := cmn.RandInt64()
	hex.Encode(hashHex, hashBytes)
	return &types.Header{LastBlockID: types.BlockID{Hash: hashHex}, Height: height}, hashHex
}

func TestIndexerServiceIndexesBlocks(t *testing.T) {
	// event bus
	eventBus := types.NewEventBus()
	eventBus.SetLogger(log.TestingLogger())
	err := eventBus.Start()
	require.NoError(t, err)
	defer eventBus.Stop()

	// tx indexer
	store := db.NewMemDB()
	blockIndexer := kv2.NewBlockIndex(store)

	service := blockindex.NewIndexerService(blockIndexer, eventBus)
	service.SetLogger(log.TestingLogger())
	err = service.Start()
	require.NoError(t, err)
	defer service.Stop()

	// publish block with txs
	header, hash := genHeader([]byte("HELLOWORD"))
	eventBus.PublishEventNewBlockHeader(types.EventDataNewBlockHeader{
		Header: *header,
	})

	time.Sleep(100 * time.Millisecond)

	// check the result
	res, err := blockIndexer.Get(hash)
	assert.NoError(t, err)
	assert.Equal(t, res.LastBlockID.Hash, hash)
}
