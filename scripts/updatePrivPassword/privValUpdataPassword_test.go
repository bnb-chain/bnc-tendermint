package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/privval"
)

const oldPrivKeyContent = `{
  "address": "8AFFFD29813C688A5BD8AD57B4AC1889471C3949",
  "pub_key": {
    "type": "tendermint/PubKeyEd25519",
    "value": "oQ7OJbgsQIi3T1p92pZOy1YqhRqCbCBROYmERVfumUI="
  },
  "encrypt_key": {
    "crypto": {
      "cipher": "aes-128-ctr",
      "ciphertext": "221fcd44c8039a3139a6cba8e39ada768de839fb3e8765125449e3e782d9632230b5319c574bb98c7a694478d9e364315bab43cb1c6b53cf0f20375df59f0fa55fc84883c1de",
      "cipherparams": {
        "iv": "728a1d28f849f0ec97acc08583f0c261"
      },
      "kdf": "scrypt",
      "kdfparams": {
        "n": "262144",
        "r": "8",
        "p": "1",
        "dklen": "12",
        "salt": "2dbc1cac6df1b9b25280f99e3758b7c4c98f24208fd0e2223939ab4b665890a9"
      },
      "mac": "77f4c97da93f3f3ee3a88bc431ae3cc9beda387f0c65bf23ed321aecb2052c74"
    },
    "version": "1"
  }
}`

const oldPrivStateContent = `{
  "height": "0",
  "round": "0",
  "step": 0
}`

func TestLoadAndUpgrade(t *testing.T) {

	oldKeyPath, oldStatePath := initTmpOldFile(t)
	defer os.Remove(oldKeyPath)
	defer os.Remove(oldStatePath)

	newStateFile, err := ioutil.TempFile("", "priv_validator_state.json")
	defer os.Remove(newStateFile.Name())
	require.NoError(t, err)
	newKeyFile, err := ioutil.TempFile("", "priv_validator_key.json")
	defer os.Remove(newKeyFile.Name())
	require.NoError(t, err)
	emptyOldFile, err := ioutil.TempFile("", "priv_validator_empty.json")
	require.NoError(t, err)
	defer os.Remove(emptyOldFile.Name())

	type args struct {
		oldPVKeyPath string
		newPVKeyPath string
		oldStatePath string
		newStatePath string
		oldPassword  string
		newPassword  string
	}

	tests := []struct {
		name      string
		args      args
		wantPanic bool
	}{
		{"successful upgrade",
			args{
				oldPVKeyPath: oldKeyPath,
				newPVKeyPath: newKeyFile.Name(),
				oldStatePath: oldStatePath,
				newStatePath: newStateFile.Name(),
				oldPassword:  "12345678",
				newPassword:  "23456789",
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				require.Panics(t, func() {
					updatePassword(tt.args.oldPVKeyPath, tt.args.newPVKeyPath, tt.args.oldStatePath, tt.args.newStatePath, tt.args.oldPassword, tt.args.newPassword)
				})
			} else {
				updatePassword(tt.args.oldPVKeyPath, tt.args.newPVKeyPath, tt.args.oldStatePath, tt.args.newStatePath, tt.args.oldPassword, tt.args.newPassword)

				upgradedPV := privval.LoadFilePV(tt.args.newPVKeyPath, tt.args.newStatePath, tt.args.newPassword)
				oldPV := privval.LoadFilePV(tt.args.oldPVKeyPath, tt.args.oldStatePath, tt.args.oldPassword)

				assert.Equal(t, oldPV.Key.Address, upgradedPV.Key.Address)
				assert.Equal(t, oldPV.GetAddress(), upgradedPV.GetAddress())
				assert.Equal(t, oldPV.Key.PubKey, upgradedPV.Key.PubKey)
				assert.Equal(t, oldPV.GetPubKey(), upgradedPV.GetPubKey())
				assert.Equal(t, oldPV.Key.PrivKey, upgradedPV.Key.PrivKey)

				assert.Equal(t, oldPV.LastSignState.Height, upgradedPV.LastSignState.Height)
				assert.Equal(t, oldPV.LastSignState.Round, upgradedPV.LastSignState.Round)
				assert.Equal(t, oldPV.LastSignState.Signature, upgradedPV.LastSignState.Signature)
				assert.Equal(t, oldPV.LastSignState.SignBytes, upgradedPV.LastSignState.SignBytes)
				assert.Equal(t, oldPV.LastSignState.Step, upgradedPV.LastSignState.Step)

			}
		})
	}
}

func initTmpOldFile(t *testing.T) (string, string) {
	tmpPrivKeyFile, err := ioutil.TempFile("", "priv_validator_key.json")
	require.NoError(t, err)
	t.Logf("created test file %s", tmpPrivKeyFile.Name())
	_, err = tmpPrivKeyFile.WriteString(oldPrivKeyContent)
	require.NoError(t, err)

	tmpPrivStateFile, err := ioutil.TempFile("", "priv_validator_state.json")
	require.NoError(t, err)
	t.Logf("created test file %s", tmpPrivStateFile.Name())
	_, err = tmpPrivStateFile.WriteString(oldPrivStateContent)
	require.NoError(t, err)

	return tmpPrivKeyFile.Name(), tmpPrivStateFile.Name()
}
