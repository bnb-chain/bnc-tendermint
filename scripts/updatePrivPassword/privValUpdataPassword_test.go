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
  "address": "14D072609EAAC15E160AF6C99379AA11E0944689",
  "pub_key": {
    "type": "tendermint/PubKeyEd25519",
    "value": "2CbTSD0nwdVb5ALk/XqpyytUzRezbtWqkbwgWabubOo="
  },
  "encrypt_key": {
    "crypto": {
      "cipher": "aes-128-ctr",
      "ciphertext": "e60df761eb871c924aa6bb3b1d99a524d81f50b852fc734ac58421cb50e263f1f03dbcb1d9d56404d6bcfdbfdf23319f413e0d68d0224bcecc63d243e5cf9232cc6882e888b2",
      "cipherparams": {
        "iv": "d1f8d8a9c335249ddc2086bfe2031409"
      },
      "kdf": "scrypt",
      "kdfparams": {
        "n": "262144",
        "r": "8",
        "p": "1",
        "dklen": "32",
        "salt": "957945e7d979a860ea72c8cbc8a33163616ee825cb5daa0aa68d7b683b442e4e"
      },
      "mac": "f0f6411755e278d60f124939d07ed443aba3e75147927b224efab92403185386"
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
