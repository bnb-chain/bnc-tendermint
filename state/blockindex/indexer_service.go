package blockindex

import (
	"context"

	cmn "github.com/tendermint/tendermint/libs/common"

	"github.com/tendermint/tendermint/types"
)

const (
	subscriber = "BlockIndexerService"
)

// IndexerService connects event bus and block indexer together in order
// to index blocks coming from event bus.
type IndexerService struct {
	cmn.BaseService

	idr      BlockIndexer
	eventBus *types.EventBus
}

// NewIndexerService returns a new service instance.
func NewIndexerService(idr BlockIndexer, eventBus *types.EventBus) *IndexerService {
	is := &IndexerService{idr: idr, eventBus: eventBus}
	is.BaseService = *cmn.NewBaseService(nil, "BlockIndexerService", is)
	return is
}

// OnStart implements cmn.Service by subscribing for blocks and indexing them by hash.
func (is *IndexerService) OnStart() error {
	blockHeadersCh := make(chan interface{})
	if err := is.eventBus.Subscribe(context.Background(), subscriber, types.EventQueryNewBlockHeader, blockHeadersCh); err != nil {
		return err
	}

	go func() {
		for {
			e, ok := <-blockHeadersCh
			if !ok {
				return
			}
			header := e.(types.EventDataNewBlockHeader).Header

			is.idr.Index(&header)
			is.Logger.Info("Indexed block", "height", header.Height, "hash", header.LastBlockID.Hash)
		}
	}()
	return nil
}

// OnStop implements cmn.Service by unsubscribing from all transactions.
func (is *IndexerService) OnStop() {
	if is.eventBus.IsRunning() {
		_ = is.eventBus.UnsubscribeAll(context.Background(), subscriber)
	}
}
