package kv

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/types"

	"github.com/ethereum/go-ethereum/swarm/testutil"
)

func genHeader(hashBytes []byte) (*types.Header, cmn.HexBytes) {
	hashHex := make([]byte, 2*len(hashBytes))
	height := cmn.RandInt64()
	hex.Encode(hashHex, hashBytes)
	return &types.Header{LastBlockID: types.BlockID{Hash: hashHex}, Height: height}, hashHex
}

func TestBlockIndex(t *testing.T) {
	indexer := NewBlockIndex(db.NewMemDB())

	blockHeader, hash := genHeader([]byte("HELLO WORLD"))

	if err := indexer.Index(blockHeader); err != nil {
		t.Error(err)
	}

	loadedBlockResult, err := indexer.Get(hash)
	require.NoError(t, err)
	assert.Equal(t, blockHeader, loadedBlockResult)

	blockHeader2, hash2 := genHeader([]byte("BYE BYE WORLD"))

	err = indexer.Index(blockHeader2)
	require.NoError(t, err)

	loadedBlock2, err := indexer.Get(hash2)
	require.NoError(t, err)
	assert.Equal(t, blockHeader2, loadedBlock2)
}

func BenchmarkBlockIndex(b *testing.B) {
	dir, err := ioutil.TempDir("", "block_index_db")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dir) // nolint: errcheck

	store := db.NewDB("block_index", "leveldb", dir)
	indexer := NewBlockIndex(store)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		block, _ := genHeader(testutil.RandomBytes(174, 30))
		err = indexer.Index(block)
	}
	if err != nil {
		b.Fatal(err)
	}
}
