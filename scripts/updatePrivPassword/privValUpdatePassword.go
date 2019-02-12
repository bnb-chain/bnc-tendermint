package main

import (
	"fmt"
	"os"

	"github.com/tendermint/tendermint/privval"
)

func main() {
	args := os.Args[1:]
	if len(args) != 6 {
		fmt.Println("Expected six args: <old key path> <new key path> <old state path> <new state path> <old password> <new password>")
		fmt.Println("Eg. ~/.tendermint/config/priv_validator_key.json ~/.tendermint/config/priv_validator_new_key.json " +
			"~/.tendermint/data/priv_validator_state.json ~/.tendermint/data/priv_validator_new_state.json 12345678 23456789")
		os.Exit(1)
	}
	updatePassword(args[0], args[1], args[2], args[3], args[4], args[5])
}

func updatePassword(oldPVKeyPath, newPVKeyPath, oldStatePath, newStatePath, oldPassword, newPassword string) {
	pv := privval.LoadFilePV(oldPVKeyPath, oldStatePath, oldPassword)

	privateKey := pv.Key.PrivKey
	newPV := privval.GenFilePVWithPrivateKey(privateKey, newPVKeyPath, newStatePath, newPassword)
	newPV.Save()
}
