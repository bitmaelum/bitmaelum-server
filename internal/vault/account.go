// Copyright (c) 2021 BitMaelum Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package vault

import (
	"errors"
	"strings"

	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
)

var errAccountNotFound = errors.New("cannot find account")

// KeyPair is a structure with key information
type KeyPair struct {
	bmcrypto.KeyPair
	Active bool `json:"active"` // This is the currently active key
}

// AccountInfoV1 represents client account information
type AccountInfoV1 struct {
	Address   *address.Address         `json:"address"`         // The address of the account
	Name      string                   `json:"name"`            // Full name of the user
	Settings  map[string]string        `json:"settings"`        // Additional settings that can be user-defined
	PrivKey   bmcrypto.PrivKey         `json:"priv_key"`        // PEM encoded private key
	PubKey    bmcrypto.PubKey          `json:"pub_key"`         // PEM encoded public key
	Pow       *proofofwork.ProofOfWork `json:"proof,omitempty"` // Proof of work
	RoutingID string                   `json:"routing_id"`      // ID of the routing used
}

// AccountInfo represents client account information
type AccountInfo struct {
	Address      *address.Address `json:"address"`                 // The address of the account
	RedirAddress *address.Address `json:"redir_address,omitempty"` // Optional address in case this address is a symlink

	Name     string            `json:"name"`     // Full name of the user
	Settings map[string]string `json:"settings"` // Additional settings that can be user-defined

	Keys []KeyPair // Actual keys

	// Communication and encryption information
	Pow       *proofofwork.ProofOfWork `json:"proof,omitempty"` // Proof of work
	RoutingID string                   `json:"routing_id"`      // ID of the routing used

	StoreKey *bmcrypto.KeyPair `json:"store_key,omitempty"` // Keypair for the store
}

// GetActiveKey will return the currently active key from the list of keys in the info structure
func (info AccountInfo) GetActiveKey() KeyPair {
	for _, k := range info.Keys {
		if k.Active {
			return k
		}
	}

	// @TODO: Return first key, as we assume this is the active key. We shouldn't. Keys might not be even filled!
	return info.Keys[0]
}

// SetActiveKey sets the active key in the info
func (info AccountInfo) SetActiveKey(kp *bmcrypto.KeyPair) {
	for idx, k := range info.Keys {
		info.Keys[idx].Active = k.FingerPrint == kp.FingerPrint
	}
}

// FindKey will try and retrieve a key based on the fingerprint
func (info AccountInfo) FindKey(fp string) (*KeyPair, error) {
	// Find key with fingerprint
	for _, k := range info.Keys {
		if k.FingerPrint == fp {
			return &k, nil
		}
	}

	return nil, errors.New("cannot find key")
}

// AddAccount adds a new account to the vault
func (v *Vault) AddAccount(account AccountInfo) {
	v.Store.Accounts = append(v.Store.Accounts, account)
}

// RemoveAccount removes the given account from the vault
func (v *Vault) RemoveAccount(addr address.Address) {
	k := 0
	for _, acc := range v.Store.Accounts {
		if acc.Address.String() != addr.String() {
			v.Store.Accounts[k] = acc
			k++
		}
	}
	v.Store.Accounts = v.Store.Accounts[:k]
}

// GetAccountInfo tries to find the given address and returns the account from the vault
func (v *Vault) GetAccountInfo(addr address.Address) (*AccountInfo, error) {
	for i := range v.Store.Accounts {
		if v.Store.Accounts[i].Address.String() == addr.String() {
			return &v.Store.Accounts[i], nil
		}
	}

	return nil, errAccountNotFound
}

// HasAccount returns true when the vault has an account for the given address
func (v *Vault) HasAccount(addr address.Address) bool {
	_, err := v.GetAccountInfo(addr)

	return err == nil
}

// GetAccount returns the given account, or nil when not found
func GetAccount(vault *Vault, a string) (*AccountInfo, error) {
	addr, err := address.NewAddress(a)
	if err != nil {
		return nil, err
	}

	return vault.GetAccountInfo(*addr)
}

// FindShortRoutingID will find a short routing ID in the vault and expand it to the full routing ID. So we can use
// "12345" instead of "1234567890123456789012345678901234567890".
// Will not return anything when multiple candidates are found.
func (v *Vault) FindShortRoutingID(id string) string {
	var found = ""
	for _, acc := range v.Store.Accounts {
		if strings.HasPrefix(acc.RoutingID, id) {
			// Found something else that matches
			if found != "" && found != acc.RoutingID {
				// Multiple entries are found, don't return them
				return ""
			}
			found = acc.RoutingID
		}
	}

	return found
}
