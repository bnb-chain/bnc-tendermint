package txindex_test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/state/txindex"
	"github.com/tendermint/tendermint/state/txindex/kv"
	"github.com/tendermint/tendermint/types"
)

func TestIndexerServiceIndexesBlocks(t *testing.T) {
	// event bus
	eventBus := types.NewEventBus()
	eventBus.SetLogger(log.TestingLogger())
	err := eventBus.Start()
	require.NoError(t, err)
	defer eventBus.Stop()

	// tx indexer
	store := db.NewMemDB()
	txIndexer := kv.NewTxIndex(store, kv.IndexAllTags())

	service := txindex.NewIndexerService(txIndexer, eventBus)
	service.SetLogger(log.TestingLogger())
	err = service.Start()
	require.NoError(t, err)
	defer service.Stop()

	// publish block with txs
	eventBus.PublishEventNewBlockHeader(types.EventDataNewBlockHeader{
		Header: types.Header{Height: 1, NumTxs: 2},
	})
	txResult1 := &types.TxResult{
		Height: 1,
		Index:  uint32(0),
		Tx:     types.Tx("foo"),
		Result: abci.ResponseDeliverTx{Code: 0},
	}
	eventBus.PublishEventTx(types.EventDataTx{*txResult1})
	txResult2 := &types.TxResult{
		Height: 1,
		Index:  uint32(1),
		Tx:     types.Tx("bar"),
		Result: abci.ResponseDeliverTx{Code: 0},
	}
	eventBus.PublishEventTx(types.EventDataTx{*txResult2})

	time.Sleep(100 * time.Millisecond)

	// check the result
	res, err := txIndexer.Get(types.Tx("foo").Hash())
	assert.NoError(t, err)
	assert.Equal(t, txResult1, res)
	res, err = txIndexer.Get(types.Tx("bar").Hash())
	assert.NoError(t, err)
	assert.Equal(t, txResult2, res)
}

func TestIndexerBenchMark(t *testing.T) {
	// event bus
	eventBus := types.NewEventBus()
	eventBus.SetLogger(log.TestingLogger())
	err := eventBus.Start()
	require.NoError(t, err)
	defer eventBus.Stop()

	// tx indexer
	store, _ := db.NewGoLevelDB("index", "/Users/baifudong/workspace/src/github.com/tendermint/data")
	txIndexer := kv.NewTxIndex(store, kv.IndexAllTags())

	service := txindex.NewIndexerService(txIndexer, eventBus)
	service.SetLogger(log.TestingLogger())
	err = service.Start()
	require.NoError(t, err)
	service.SetOnIndex(
		func(i int64) {
			fmt.Println("indexed",i)
			if i == int64(998) {
				fmt.Println(time.Now())
			}
		})
	defer service.Stop()

	go func() {
		fmt.Println("start",time.Now())
		r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
		for h := int64(0); h < 1000; h++ {
			fmt.Println("publish",h)
			numtx:=2000
			eventBus.PublishEventNewBlockHeader(types.EventDataNewBlockHeader{
				Header: types.Header{Height: h, NumTxs: int64(numtx)},
			})
			for i := 0; i < numtx; i++ {
				txbyte := make([]byte, 400)
				_, err := r.Read(txbyte)
				if err != nil {
					fmt.Println(err)
				}
				txResult1 := &types.TxResult{
					Height: h,
					Index:  uint32(i),
					Tx:     types.Tx(txbyte),
					Result: abci.ResponseDeliverTx{Code: 0},
				}
				eventBus.PublishEventTx(types.EventDataTx{*txResult1})
			}
		}
		txResult2 := &types.TxResult{
			Height: 1,
			Index:  uint32(1),
			Tx:     types.Tx("bar"),
			Result: abci.ResponseDeliverTx{Code: 0},
		}
		eventBus.PublishEventTx(types.EventDataTx{*txResult2})
		//fmt.Println(time.Now())
	}()
	select {
	}
}
