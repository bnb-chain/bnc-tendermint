package hot

import (
	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/types"
)

var cdc = amino.NewCodec()

func init() {
	RegisterHotBlockchainMessages(cdc)
	types.RegisterBlockAmino(cdc)
}
