package api

import (
	"github.com/bitmaelum/bitmaelum-suite/internal"
	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	pow "github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
)

// GetPublicKey gets public key for given address on the mail server
func (api *API) GetPublicKey(addr address.HashAddress) (string, error) {
	type PubKeyOutput struct {
		PublicKey string `json:"public_key"`
	}
	output := PubKeyOutput{}

	resp, statusCode, err := api.GetJSON("/account/"+addr.String()+"/key", output)
	if err != nil {
		return "", err
	}

	if statusCode < 200 || statusCode > 299 {
		return "", getErrorFromResponse(resp)
	}

	return output.PublicKey, nil
}

// CreateAccount creates new account on server
func (api *API) CreateAccount(info internal.AccountInfo, token string) error {
	type inputCreateAccount struct {
		Addr        address.HashAddress `json:"address"`
		UserHash    string              `json:"user_hash"`
		OrgHash     string              `json:"org_hash"`
		Token       string              `json:"token"`
		PublicKey   bmcrypto.PubKey     `json:"public_key"`
		ProofOfWork pow.ProofOfWork     `json:"proof_of_work"`
	}

	addr, _ := address.New(info.Address)

	input := &inputCreateAccount{
		Addr:        addr.Hash(),
		UserHash:    addr.LocalHash(),
		OrgHash:     addr.OrgHash(),
		Token:       token,
		PublicKey:   info.PubKey,
		ProofOfWork: info.Pow,
	}

	resp, statusCode, err := api.PostJSON("/account", input)
	if err != nil {
		return err
	}

	if statusCode < 200 || statusCode > 299 {
		return getErrorFromResponse(resp)
	}

	return nil
}
