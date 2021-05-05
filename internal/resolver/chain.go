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

package resolver

import (
	"errors"

	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
)

// ErrConfigNotFound is returned when no resolver configuration could be found
var ErrConfigNotFound = errors.New("configuration not found")

// ChainRepository holds a list of multiple repositories which can all be tried to resolve addresses and keys
type ChainRepository struct {
	repos []Repository
}

// NewChainRepository Return a new chain repository
func NewChainRepository() Repository {
	return &ChainRepository{
		repos: []Repository{},
	}
}

// Add a new repository to the chain
func (r *ChainRepository) Add(repo Repository) error {
	r.repos = append(r.repos, repo)

	return nil
}

// ResolveAddress an address through the chained repos
func (r *ChainRepository) ResolveAddress(addr hash.Hash) (*AddressInfo, error) {
	for idx := range r.repos {
		info, err := r.repos[idx].ResolveAddress(addr)
		if err == nil {
			return info, nil
		}
	}

	return nil, ErrKeyNotFound
}

// ResolveRouting resolves routing
func (r *ChainRepository) ResolveRouting(routingID string) (*RoutingInfo, error) {
	for idx := range r.repos {
		info, err := r.repos[idx].ResolveRouting(routingID)
		if err == nil {
			return info, nil
		}
	}

	return nil, ErrKeyNotFound
}

// ResolveOrganisation resolves organisation
func (r *ChainRepository) ResolveOrganisation(orgHash hash.Hash) (*OrganisationInfo, error) {
	for idx := range r.repos {
		info, err := r.repos[idx].ResolveOrganisation(orgHash)
		if err == nil {
			return info, nil
		}
	}

	return nil, ErrKeyNotFound
}

// UploadAddress public key through the chained repos
func (r *ChainRepository) UploadAddress(addr address.Address, info *AddressInfo, privKey bmcrypto.PrivKey) error {
	for idx := range r.repos {
		err := r.repos[idx].UploadAddress(addr, info, privKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// UploadRouting uploads routing information
func (r *ChainRepository) UploadRouting(info *RoutingInfo, privKey bmcrypto.PrivKey) error {
	for idx := range r.repos {
		err := r.repos[idx].UploadRouting(info, privKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// UploadOrganisation uploads organisation information
func (r *ChainRepository) UploadOrganisation(info *OrganisationInfo, privKey bmcrypto.PrivKey, pow proofofwork.ProofOfWork) error {
	for idx := range r.repos {
		err := r.repos[idx].UploadOrganisation(info, privKey, pow)
		if err != nil {
			return err
		}
	}

	return nil
}

// DeleteRouting from repos
func (r *ChainRepository) DeleteRouting(info *RoutingInfo, privKey bmcrypto.PrivKey) error {
	for idx := range r.repos {
		err := r.repos[idx].DeleteRouting(info, privKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// DeleteOrganisation from repos
func (r *ChainRepository) DeleteOrganisation(info *OrganisationInfo, privKey bmcrypto.PrivKey) error {
	for idx := range r.repos {
		err := r.repos[idx].DeleteOrganisation(info, privKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetConfig will return the resolver configuration from the repos
func (r *ChainRepository) GetConfig() (*ProofOfWorkConfig, error) {
	for idx := range r.repos {
		cfg, err := r.repos[idx].GetConfig()
		if err == nil {
			return cfg, nil
		}
	}

	return nil, ErrConfigNotFound
}

// CheckReserved will check if the hash is a reserved hash
func (r *ChainRepository) CheckReserved(h hash.Hash) ([]string, error) {
	for idx := range r.repos {
		domains, err := r.repos[idx].CheckReserved(h)
		if err == nil {
			return domains, nil
		}
	}

	return []string{}, nil
}

// DeleteAddress will remove the address from the key resolver
func (r *ChainRepository) DeleteAddress(info *AddressInfo, privKey bmcrypto.PrivKey) error {
	for idx := range r.repos {
		err := r.repos[idx].DeleteAddress(info, privKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// UndeleteAddress will undelete the address on the key resolver
func (r *ChainRepository) UndeleteAddress(info *AddressInfo, privKey bmcrypto.PrivKey) error {
	for idx := range r.repos {
		err := r.repos[idx].UndeleteAddress(info, privKey)
		if err != nil {
			return err
		}
	}

	return nil
}
