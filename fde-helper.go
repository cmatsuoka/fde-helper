package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/jessevdk/go-flags"
	sb "github.com/snapcore/secboot"
)

var _ sb.KeyUnsealer = (*fdeHelperKeyUnsealer)(nil)

const (
	unsealedKeyPath = "/run/mnt/ubuntu-boot/insecure-key"
	unsealedKeyLen  = 64
)

type fdeHelperKeyUnsealer struct{}

func (u *fdeHelperKeyUnsealer) UnsealKey(volumeName, sourceDevicePath string, p sb.Prompter) (key, resealToken []byte, err error) {
	key, err = ioutil.ReadFile(unsealedKeyPath)
	if len(key) != unsealedKeyLen {
		err = fmt.Errorf("unexpected key length (%d)", len(key))
	}
	return key, nil, err
}

func (u *fdeHelperKeyUnsealer) UnderstoodError(e error, isCryptsetupError bool) (ok bool, reason sb.RecoveryKeyUsageReason, err error) {
	return false, 0, nil
}

// supported verifies if secure full disk encryption is supported on this
// system.
func supported() error {
	return nil
}

type bootAsset struct {
	Role   string   `json:"role"`
	Name   string   `json:"name"`
	Hashes []string `json:"hashes"`
}

type bootChain struct {
	BrandID        string      `json:"brand-id"`
	Model          string      `json:"model"`
	Grade          string      `json:"grade"`
	ModelSignKeyID string      `json:"model-sign-key-id"`
	AssetChain     []bootAsset `json:"asset-chain"`
	Kernel         string      `json:"kernel"`
	// KernelRevision is the revision of the kernel snap. It is empty if
	// kernel is unasserted, in which case always reseal.
	KernelRevision string   `json:"kernel-revision"`
	KernelCmdlines []string `json:"kernel-cmdlines"`
}

type provisionParams struct {
	Key        string      `json:"key"`
	BootChains []bootChain `json:"boot-chains"`
}

// initialProvision initializes the key sealing system (e.g. provision the TPM
// if TPM is used) and stores the key in a secure place.
func initialProvision(p []byte) error {
	var params provisionParams
	if err := json.Unmarshal(p, &params); err != nil {
		return err
	}

	key, err := base64.RawStdEncoding.DecodeString(params.Key)
	if err != nil {
		return err
	}

	if len(key) != unsealedKeyLen {
		return fmt.Errorf("unexpected key length (%d)", len(key))
	}

	if err := ioutil.WriteFile(unsealedKeyPath, key, 0600); err != nil {
		return err
	}

	return nil
}

type updateParams struct {
	BootChains []bootChain `json:"boot-chains"`
}

// update reseals or updates the stored key policies.
func update(p []byte) error {
	var params provisionParams
	if err := json.Unmarshal(p, &params); err != nil {
		return err
	}

	// do nothing

	return nil
}

type unlockParams struct {
	volumeName       string `json:"volume-name"`
	sourceDevicePath string `json:"source-device-path"`
	lockKeysOnFinish bool   `json:"lock-keys-on-finish"`
}

// unlock unseals the key and unlock the encrypted volume.
func unlock(p []byte) error {
	var params unlockParams
	if err := json.Unmarshal(p, &params); err != nil {
		return err
	}

	keyUnsealer := &fdeHelperKeyUnsealer{}

	options := &sb.ActivateWithTPMSealedKeyOptions{
		PINTries:            1,
		RecoveryKeyTries:    3,
		LockSealedKeyAccess: params.lockKeysOnFinish,
	}
	ok, err := sb.ActivateVolumeWithKeyUnsealer(params.volumeName, params.sourceDevicePath, keyUnsealer, nil, options)
	if err != nil {
		return err
	}
	// XXX: check if this can happen
	if !ok {
		return fmt.Errorf("volume was not activated")
	}
	return nil
}

type options struct {
	// XXX: all descriptions are placeholders
	Supported bool `long:"supported" description:"Check if fde available"`
	Init      bool `long:"initial-provision" description:"Provision TPM and seal"`
	Update    bool `long:"update" description:"Reseal (update the policy) in the TPM case"`
	Unlock    bool `long:"unlock" description:"Unseal and unlock"`
}

func main() {
	var opt options
	parser := flags.NewParser(&opt, flags.Default)
	if _, err := parser.Parse(); err != nil {
		switch flagsErr := err.(type) {
		case flags.ErrorType:
			if flagsErr == flags.ErrHelp {
				parser.WriteHelp(os.Stdout)
				os.Exit(0)
			}
			os.Exit(1)
		default:
			os.Exit(1)
		}
	}

	if opt.Supported {
		if err := supported(); err != nil {
			fmt.Printf("secure fde unsupported: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	// read JSON-formated parameters from stdin
	reader := bufio.NewReader(os.Stdin)
	p, err := reader.ReadBytes('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	switch {
	case opt.Init:
		err = initialProvision(p)
	case opt.Update:
		err = update(p)
	case opt.Unlock:
		err = unlock(p)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
