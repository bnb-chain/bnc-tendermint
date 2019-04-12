package blockindex

import (
	"errors"

	"github.com/tendermint/tendermint/types"
)

// BlockIndexer interface defines methods to index and search blocks.
type BlockIndexer interface {

	// Index analyzes, indexes and stores a single (block hash -- block height) key-value.
	Index(block *types.Header) error

	// Get returns the block height specified by hash or 0 if the block is not indexed.
	Get(hash []byte) (int64, error)
}

//----------------------------------------------------
// Errors
// ErrorEmptyHash indicates empty hash
var ErrorEmptyHash = errors.New("Block hash cannot be empty")
