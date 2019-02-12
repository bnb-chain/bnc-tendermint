package privval

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/crypto/tmhash"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
	"golang.org/x/crypto/scrypt"
)

// TODO: type ?
const (
	stepNone      int8 = 0 // Used to distinguish the initial state
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
)

// A vote is either stepPrevote or stepPrecommit.
func voteToStep(vote *types.Vote) int8 {
	switch vote.Type {
	case types.PrevoteType:
		return stepPrevote
	case types.PrecommitType:
		return stepPrecommit
	default:
		panic("Unknown vote type")
		return 0
	}
}

const (
	scryptR     = 8
	scryptDKLen = 12

	version = 1

	keyHeaderKDF = "scrypt"

	SaltBytes = 32

	// StandardScryptN is the N parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptN = 1 << 18

	// StandardScryptP is the P parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptP = 1
)

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

// TMHash calculates and returns the TMHash hash of the input data.
func TMHash(data ...[]byte) []byte {
	d := tmhash.New()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

type CryptoJSON struct {
	Cipher       string           `json:"cipher"`
	CipherText   string           `json:"ciphertext"`
	CipherParams CipherparamsJSON `json:"cipherparams"`
	KDF          string           `json:"kdf"`
	KDFParams    KDFParams        `json:"kdfparams"`
	MAC          string           `json:"mac"`
}

type KDFParams struct {
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DKLen int    `json:"dklen"`
	Salt  string `json:"salt"`
}

type CipherparamsJSON struct {
	IV string `json:"iv"`
}

type EncryptedKey struct {
	Crypto  CryptoJSON `json:"crypto"`
	Version int        `json:"version"`
}

func EncryptKey(keyBytes []byte, auth string, scryptN, scryptP int) (EncryptedKey, error) {
	authArray := []byte(auth)
	salt := crypto.CRandBytes(SaltBytes)
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return EncryptedKey{}, err
	}
	encryptKey := derivedKey[:16]

	iv := crypto.CRandBytes(aes.BlockSize) // 16
	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return EncryptedKey{}, err
	}
	mac := TMHash(derivedKey[16:32], cipherText)

	scryptParamsJSON := KDFParams{scryptN, scryptR, scryptP, scryptDKLen, hex.EncodeToString(salt)}

	cipherParamsJSON := CipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	cryptoStruct := CryptoJSON{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          keyHeaderKDF,
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	encryptedKeyJSONV := EncryptedKey{
		cryptoStruct,
		version,
	}
	return encryptedKeyJSONV, nil
}

// DecryptKey decrypts a key from a json blob, returning the private key itself.
func DecryptKey(keyjson []byte, auth string) ([]byte, error) {
	// Parse the json into a simple map to fetch the key version
	m := make(map[string]interface{})
	if err := json.Unmarshal(keyjson, &m); err != nil {
		return nil, err
	}
	// Depending on the version try to parse one way or another
	var (
		keyBytes []byte
		err      error
	)

	k := new(EncryptedKey)
	if err := json.Unmarshal(keyjson, k); err != nil {
		return nil, err
	}
	keyBytes, _, err = decryptKey(k, auth)

	// Handle any decryption errors and return the key
	if err != nil {
		return nil, err
	}

	return keyBytes, nil
}

func decryptKey(keyProtected *EncryptedKey, auth string) (keyBytes []byte, keyId []byte, err error) {
	if keyProtected.Version != version {
		return nil, nil, fmt.Errorf("Version not supported: %v", keyProtected.Version)
	}

	if keyProtected.Crypto.Cipher != "aes-128-ctr" {
		return nil, nil, fmt.Errorf("Cipher not supported: %v", keyProtected.Crypto.Cipher)
	}

	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		return nil, nil, err
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, nil, err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, nil, err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, auth)
	if err != nil {
		return nil, nil, err
	}

	calculatedMAC := TMHash(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, nil, nil
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, nil, err
	}
	return plainText, keyId, err
}

func getKDFKey(cryptoJSON CryptoJSON, auth string) ([]byte, error) {
	authArray := []byte(auth)
	salt, err := hex.DecodeString(cryptoJSON.KDFParams.Salt)
	if err != nil {
		return nil, err
	}
	dkLen := ensureInt(cryptoJSON.KDFParams.DKLen)

	if cryptoJSON.KDF == keyHeaderKDF {
		n := ensureInt(cryptoJSON.KDFParams.N)
		r := ensureInt(cryptoJSON.KDFParams.R)
		p := ensureInt(cryptoJSON.KDFParams.P)
		return scrypt.Key(authArray, salt, n, r, p, dkLen)

	}

	return nil, fmt.Errorf("Unsupported KDF: %s", cryptoJSON.KDF)
}

func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}

//-------------------------------------------------------------------------------

// FilePVKey stores the immutable part of PrivValidator.
type FilePVKey struct {
	Address types.Address  `json:"address"`
	PubKey  crypto.PubKey  `json:"pub_key"`
	PrivKey crypto.PrivKey `json:"-"`

	EncryptedKey EncryptedKey `json:"encrypt_key"`
	filePath     string
}

// Save persists the FilePVKey to its filePath.
func (pvKey FilePVKey) Save() {
	outFile := pvKey.filePath
	if outFile == "" {
		panic("Cannot save PrivValidator key: filePath not set")
	}

	jsonBytes, err := cdc.MarshalJSONIndent(pvKey, "", "  ")
	if err != nil {
		panic(err)
	}
	err = cmn.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}

}

//-------------------------------------------------------------------------------

// FilePVLastSignState stores the mutable part of PrivValidator.
type FilePVLastSignState struct {
	Height    int64        `json:"height"`
	Round     int          `json:"round"`
	Step      int8         `json:"step"`
	Signature []byte       `json:"signature,omitempty"`
	SignBytes cmn.HexBytes `json:"signbytes,omitempty"`

	filePath string
}

// CheckHRS checks the given height, round, step (HRS) against that of the
// FilePVLastSignState. It returns an error if the arguments constitute a regression,
// or if they match but the SignBytes are empty.
// The returned boolean indicates whether the last Signature should be reused -
// it returns true if the HRS matches the arguments and the SignBytes are not empty (indicating
// we have already signed for this HRS, and can reuse the existing signature).
// It panics if the HRS matches the arguments, there's a SignBytes, but no Signature.
func (lss *FilePVLastSignState) CheckHRS(height int64, round int, step int8) (bool, error) {

	if lss.Height > height {
		return false, errors.New("Height regression")
	}

	if lss.Height == height {
		if lss.Round > round {
			return false, errors.New("Round regression")
		}

		if lss.Round == round {
			if lss.Step > step {
				return false, errors.New("Step regression")
			} else if lss.Step == step {
				if lss.SignBytes != nil {
					if lss.Signature == nil {
						panic("pv: Signature is nil but SignBytes is not!")
					}
					return true, nil
				}
				return false, errors.New("No SignBytes found")
			}
		}
	}
	return false, nil
}

// Save persists the FilePvLastSignState to its filePath.
func (lss *FilePVLastSignState) Save() {
	outFile := lss.filePath
	if outFile == "" {
		panic("Cannot save FilePVLastSignState: filePath not set")
	}
	jsonBytes, err := cdc.MarshalJSONIndent(lss, "", "  ")
	if err != nil {
		panic(err)
	}
	err = cmn.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		panic(err)
	}
}

//-------------------------------------------------------------------------------

// FilePV implements PrivValidator using data persisted to disk
// to prevent double signing.
// NOTE: the directories containing pv.Key.filePath and pv.LastSignState.filePath must already exist.
// It includes the LastSignature and LastSignBytes so we don't lose the signature
// if the process crashes after signing but before the resulting consensus message is processed.
type FilePV struct {
	Key           FilePVKey
	LastSignState FilePVLastSignState
}

// GenFilePV generates a new validator with randomly generated private key
// and sets the filePaths, but does not call Save().
func GenFilePV(keyFilePath, stateFilePath, password string) *FilePV {
	privKey := ed25519.GenPrivKey()
	privKeyBinary, err := cdc.MarshalBinaryLengthPrefixed(privKey)
	if err != nil {
		panic(fmt.Sprintf("Error marshaling private key.\n"))
	}

	encryptedKey, err := EncryptKey(privKeyBinary, password, StandardScryptN, StandardScryptP)
	if err != nil {
		panic(fmt.Sprintf("Error encrypt private key.\n"))
	}

	return &FilePV{
		Key: FilePVKey{
			Address:      privKey.PubKey().Address(),
			PubKey:       privKey.PubKey(),
			PrivKey:      privKey,
			EncryptedKey: encryptedKey,

			filePath: keyFilePath,
		},
		LastSignState: FilePVLastSignState{
			Step:     stepNone,
			filePath: stateFilePath,
		},
	}
}

// GenFilePVWithPrivateKey generates a new validator with given private key
// and sets the filePaths, but does not call Save().
func GenFilePVWithPrivateKey(privKey crypto.PrivKey, keyFilePath, stateFilePath, password string) *FilePV {
	privKeyBinary, err := cdc.MarshalBinaryLengthPrefixed(privKey)
	if err != nil {
		panic(fmt.Sprintf("Error marshaling private key.\n"))
	}

	encryptedKey, err := EncryptKey(privKeyBinary, password, StandardScryptN, StandardScryptP)
	if err != nil {
		panic(fmt.Sprintf("Error encrypt private key.\n"))
	}

	return &FilePV{
		Key: FilePVKey{
			Address:      privKey.PubKey().Address(),
			PubKey:       privKey.PubKey(),
			PrivKey:      privKey,
			EncryptedKey: encryptedKey,

			filePath: keyFilePath,
		},
		LastSignState: FilePVLastSignState{
			Step:     stepNone,
			filePath: stateFilePath,
		},
	}
}

func LoadPubkey(keyFilePath string) (crypto.PubKey, error) {
	keyJSONBytes, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		cmn.Exit(err.Error())
	}
	pvKey := FilePVKey{}
	err = cdc.UnmarshalJSON(keyJSONBytes, &pvKey)
	if err != nil {
		return nil, nil
	}

	return pvKey.PubKey, nil
}

// LoadFilePV loads a FilePV from the filePaths.  The FilePV handles double
// signing prevention by persisting data to the stateFilePath.  If either file path
// does not exist, the program will exit.
func LoadFilePV(keyFilePath, stateFilePath string, password string) *FilePV {
	return loadFilePV(keyFilePath, stateFilePath, true, password)
}

// LoadFilePVEmptyState loads a FilePV from the given keyFilePath, with an empty LastSignState.
// If the keyFilePath does not exist, the program will exit.
func LoadFilePVEmptyState(keyFilePath, stateFilePath string, password string) *FilePV {
	return loadFilePV(keyFilePath, stateFilePath, false, password)
}

// If loadState is true, we load from the stateFilePath. Otherwise, we use an empty LastSignState.
func loadFilePV(keyFilePath, stateFilePath string, loadState bool, password string) *FilePV {
	keyJSONBytes, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		cmn.Exit(err.Error())
	}
	pvKey := FilePVKey{}
	err = cdc.UnmarshalJSON(keyJSONBytes, &pvKey)
	if err != nil {
		cmn.Exit(fmt.Sprintf("Error reading PrivValidator key from %v: %v\n", keyFilePath, err))
	}

	encryptedKeyBytes, err := json.Marshal(pvKey.EncryptedKey)
	if err != nil {
		cmn.Exit(fmt.Sprintf("Error marshaling encrypted key struct\n"))
	}

	privKeyBinary, err := DecryptKey(encryptedKeyBytes, password)
	if err != nil || len(privKeyBinary) == 0 {
		cmn.Exit(fmt.Sprintf("Error decrypting private key, please make sure password is right.\n"))
	}

	var privKey crypto.PrivKey
	err = cdc.UnmarshalBinaryLengthPrefixed(privKeyBinary, &privKey)
	if err != nil {
		cmn.Exit(fmt.Sprintf("Error unmarshaling private key.\n"))
	}

	pvKey.PrivKey = privKey

	// overwrite pubkey and address for convenience
	pvKey.PubKey = pvKey.PrivKey.PubKey()
	pvKey.Address = pvKey.PubKey.Address()
	pvKey.filePath = keyFilePath

	pvState := FilePVLastSignState{}
	if loadState {
		stateJSONBytes, err := ioutil.ReadFile(stateFilePath)
		if err != nil {
			cmn.Exit(err.Error())
		}
		err = cdc.UnmarshalJSON(stateJSONBytes, &pvState)
		if err != nil {
			cmn.Exit(fmt.Sprintf("Error reading PrivValidator state from %v: %v\n", stateFilePath, err))
		}
	}

	pvState.filePath = stateFilePath

	return &FilePV{
		Key:           pvKey,
		LastSignState: pvState,
	}
}

// LoadOrGenFilePV loads a FilePV from the given filePaths
// or else generates a new one and saves it to the filePaths.
func LoadOrGenFilePV(keyFilePath, stateFilePath string, password string) *FilePV {
	var pv *FilePV
	if cmn.FileExists(keyFilePath) {
		pv = LoadFilePV(keyFilePath, stateFilePath, password)
	} else {
		pv = GenFilePV(keyFilePath, stateFilePath, password)
		pv.Save()
	}
	return pv
}

// GetAddress returns the address of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetAddress() types.Address {
	return pv.Key.Address
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetPubKey() crypto.PubKey {
	return pv.Key.PubKey
}

// SignVote signs a canonical representation of the vote, along with the
// chainID. Implements PrivValidator.
func (pv *FilePV) SignVote(chainID string, vote *types.Vote) error {
	if err := pv.signVote(chainID, vote); err != nil {
		return fmt.Errorf("Error signing vote: %v", err)
	}
	return nil
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID. Implements PrivValidator.
func (pv *FilePV) SignProposal(chainID string, proposal *types.Proposal) error {
	if err := pv.signProposal(chainID, proposal); err != nil {
		return fmt.Errorf("Error signing proposal: %v", err)
	}
	return nil
}

// Save persists the FilePV to disk.
func (pv *FilePV) Save() {
	pv.Key.Save()
	pv.LastSignState.Save()
}

// Reset resets all fields in the FilePV.
// NOTE: Unsafe!
func (pv *FilePV) Reset() {
	var sig []byte
	pv.LastSignState.Height = 0
	pv.LastSignState.Round = 0
	pv.LastSignState.Step = 0
	pv.LastSignState.Signature = sig
	pv.LastSignState.SignBytes = nil
	pv.Save()
}

// String returns a string representation of the FilePV.
func (pv *FilePV) String() string {
	return fmt.Sprintf("PrivValidator{%v LH:%v, LR:%v, LS:%v}", pv.GetAddress(), pv.LastSignState.Height, pv.LastSignState.Round, pv.LastSignState.Step)
}

//------------------------------------------------------------------------------------

// signVote checks if the vote is good to sign and sets the vote signature.
// It may need to set the timestamp as well if the vote is otherwise the same as
// a previously signed vote (ie. we crashed after signing but before the vote hit the WAL).
func (pv *FilePV) signVote(chainID string, vote *types.Vote) error {
	height, round, step := vote.Height, vote.Round, voteToStep(vote)

	lss := pv.LastSignState

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return err
	}

	signBytes := vote.SignBytes(chainID)

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			vote.Signature = lss.Signature
		} else if timestamp, ok := checkVotesOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
			vote.Timestamp = timestamp
			vote.Signature = lss.Signature
		} else {
			err = fmt.Errorf("Conflicting data")
		}
		return err
	}

	// It passed the checks. Sign the vote
	sig, err := pv.Key.PrivKey.Sign(signBytes)
	if err != nil {
		return err
	}
	pv.saveSigned(height, round, step, signBytes, sig)
	vote.Signature = sig
	return nil
}

// signProposal checks if the proposal is good to sign and sets the proposal signature.
// It may need to set the timestamp as well if the proposal is otherwise the same as
// a previously signed proposal ie. we crashed after signing but before the proposal hit the WAL).
func (pv *FilePV) signProposal(chainID string, proposal *types.Proposal) error {
	height, round, step := proposal.Height, proposal.Round, stepPropose

	lss := pv.LastSignState

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return err
	}

	signBytes := proposal.SignBytes(chainID)

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			proposal.Signature = lss.Signature
		} else if timestamp, ok := checkProposalsOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
			proposal.Timestamp = timestamp
			proposal.Signature = lss.Signature
		} else {
			err = fmt.Errorf("Conflicting data")
		}
		return err
	}

	// It passed the checks. Sign the proposal
	sig, err := pv.Key.PrivKey.Sign(signBytes)
	if err != nil {
		return err
	}
	pv.saveSigned(height, round, step, signBytes, sig)
	proposal.Signature = sig
	return nil
}

// Persist height/round/step and signature
func (pv *FilePV) saveSigned(height int64, round int, step int8,
	signBytes []byte, sig []byte) {

	pv.LastSignState.Height = height
	pv.LastSignState.Round = round
	pv.LastSignState.Step = step
	pv.LastSignState.Signature = sig
	pv.LastSignState.SignBytes = signBytes
	pv.LastSignState.Save()
}

//-----------------------------------------------------------------------------------------

// returns the timestamp from the lastSignBytes.
// returns true if the only difference in the votes is their timestamp.
func checkVotesOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastVote, newVote types.CanonicalVote
	if err := cdc.UnmarshalBinaryLengthPrefixed(lastSignBytes, &lastVote); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into vote: %v", err))
	}
	if err := cdc.UnmarshalBinaryLengthPrefixed(newSignBytes, &newVote); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into vote: %v", err))
	}

	lastTime := lastVote.Timestamp

	// set the times to the same value and check equality
	now := tmtime.Now()
	lastVote.Timestamp = now
	newVote.Timestamp = now
	lastVoteBytes, _ := cdc.MarshalJSON(lastVote)
	newVoteBytes, _ := cdc.MarshalJSON(newVote)

	return lastTime, bytes.Equal(newVoteBytes, lastVoteBytes)
}

// returns the timestamp from the lastSignBytes.
// returns true if the only difference in the proposals is their timestamp
func checkProposalsOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastProposal, newProposal types.CanonicalProposal
	if err := cdc.UnmarshalBinaryLengthPrefixed(lastSignBytes, &lastProposal); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into proposal: %v", err))
	}
	if err := cdc.UnmarshalBinaryLengthPrefixed(newSignBytes, &newProposal); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into proposal: %v", err))
	}

	lastTime := lastProposal.Timestamp
	// set the times to the same value and check equality
	now := tmtime.Now()
	lastProposal.Timestamp = now
	newProposal.Timestamp = now
	lastProposalBytes, _ := cdc.MarshalBinaryLengthPrefixed(lastProposal)
	newProposalBytes, _ := cdc.MarshalBinaryLengthPrefixed(newProposal)

	return lastTime, bytes.Equal(newProposalBytes, lastProposalBytes)
}
