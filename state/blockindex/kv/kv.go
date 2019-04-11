package kv

import (
	"fmt"

	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/state/blockindex"
	"github.com/tendermint/tendermint/types"
)

var _ blockindex.BlockIndexer = (*BlockIndex)(nil)

// BlockIndex is the simplest possible indexer, backed by key-value storage (levelDB).
type BlockIndex struct {
	store       dbm.DB
	tagsToIndex []string
}

// NewBlockIndex creates new KV indexer.
func NewBlockIndex(store dbm.DB, options ...func(*BlockIndex)) *BlockIndex {
	bki := &BlockIndex{store: store, tagsToIndex: make([]string, 0)}
	for _, o := range options {
		o(bki)
	}
	return bki
}

// Get gets transaction from the BlockIndex storage and returns it or nil if the
// transaction is not found.
func (bki *BlockIndex) Get(hash []byte) (*types.Header, error) {
	if len(hash) == 0 {
		return nil, blockindex.ErrorEmptyHash
	}

	rawBytes := bki.store.Get(hash)
	if rawBytes == nil {
		return nil, nil
	}

	blockHeader := new(types.Header)
	err := cdc.UnmarshalBinaryBare(rawBytes, &blockHeader)
	if err != nil {
		return nil, fmt.Errorf("Error reading block header: %v", err)
	}

	return blockHeader, nil
}

// Index indexes a single transaction using the given list of tags.
func (bki *BlockIndex) Index(block *types.Header) error {

	hash := block.LastBlockID.Hash

	// index block by hash
	rawBytes, err := cdc.MarshalBinaryBare(block)
	if err != nil {
		return err
	}
	bki.store.Set(hash, rawBytes)
	return nil
}
