package blockindex

import (
	"errors"

	"github.com/tendermint/tendermint/types"
)

// BlockIndexer interface defines methods to index and search blocks.
type BlockIndexer interface {

	// Index analyzes, indexes and stores a single block.
	Index(block *types.Header) error

	// Get returns the block header specified by hash or nil if the block is not indexed
	// or stored.
	Get(hash []byte) (*types.Header, error)
}

//----------------------------------------------------
// Errors
// ErrorEmptyHash indicates empty hash
var ErrorEmptyHash = errors.New("Block hash cannot be empty")
