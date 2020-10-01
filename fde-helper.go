package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/jessevdk/go-flags"
	sb "github.com/snapcore/secboot"
	"github.com/snapcore/snapd/fdehelper"
)

var _ sb.KeyUnsealer = (*fdeHelperKeyUnsealer)(nil)

const (
	unsealedKeyPath = "/run/mnt/ubuntu-boot/insecure-key"
	unsealedKeyLen  = 64
)

type fdeHelperKeyUnsealer struct{}

func (u *fdeHelperKeyUnsealer) UnsealKey(volumeName, sourceDevicePath string, p sb.Prompter) (key, resealToken []byte, err error) {
	key, err = ioutil.ReadFile(unsealedKeyPath)
	if err != nil {
		return key, nil, fmt.Errorf("cannot read key file: %v", err)
	}
	if len(key) != unsealedKeyLen {
		return key, nil, fmt.Errorf("unexpected key length (%d)", len(key))
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

// initialProvision initializes the key sealing system (e.g. provision the TPM
// if TPM is used) and stores the key in a secure place.
func initialProvision(p []byte) error {
	var params fdehelper.InitialProvisionParams
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

// update reseals or updates the stored key policies.
func update(p []byte) error {
	var params fdehelper.UpdateParams
	if err := json.Unmarshal(p, &params); err != nil {
		return err
	}

	// do nothing

	return nil
}

// unlock unseals the key and unlock the encrypted volume.
func unlock(p []byte) error {
	var params fdehelper.UnlockParams
	if err := json.Unmarshal(p, &params); err != nil {
		return err
	}

	if params.VolumeName == "" {
		return fmt.Errorf("volume name not specified")
	}
	if params.SourceDevicePath == "" {
		return fmt.Errorf("source device path not specified")
	}

	keyUnsealer := &fdeHelperKeyUnsealer{}

	prompter := &sb.SystemPrompter{}

	options := &sb.ActivateWithTPMSealedKeyOptions{
		PINTries:            1,
		RecoveryKeyTries:    3,
		LockSealedKeyAccess: params.LockKeysOnFinish,
	}
	ok, err := sb.ActivateVolumeWithKeyUnsealer(params.VolumeName, params.SourceDevicePath, keyUnsealer, prompter, options)
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
	if err != nil && err != io.EOF {
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
