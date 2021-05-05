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
	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
)

type mockRepo struct {
	address        map[string]AddressInfo
	deletedAddress map[string]AddressInfo
	routing        map[string]RoutingInfo
	organisation   map[string]OrganisationInfo
}

// NewMockRepository creates a simple mock repository for testing purposes
func NewMockRepository() (Repository, error) {
	r := &mockRepo{}

	r.address = make(map[string]AddressInfo)
	r.deletedAddress = make(map[string]AddressInfo)
	r.routing = make(map[string]RoutingInfo)
	r.organisation = make(map[string]OrganisationInfo)

	return r, nil

}

func (r *mockRepo) ResolveAddress(addr hash.Hash) (*AddressInfo, error) {
	if ai, ok := r.address[addr.String()]; ok {
		return &ai, nil
	}

	return nil, ErrKeyNotFound
}

func (r *mockRepo) ResolveRouting(routingID string) (*RoutingInfo, error) {
	if ri, ok := r.routing[routingID]; ok {
		return &ri, nil
	}

	return nil, ErrKeyNotFound
}

func (r *mockRepo) ResolveOrganisation(orgHash hash.Hash) (*OrganisationInfo, error) {
	if oi, ok := r.organisation[orgHash.String()]; ok {
		return &oi, nil
	}

	return nil, ErrKeyNotFound
}

func (r *mockRepo) UploadAddress(_ address.Address, info *AddressInfo, _ bmcrypto.PrivKey) error {
	r.address[info.Hash] = *info
	return nil
}

func (r *mockRepo) UploadRouting(info *RoutingInfo, _ bmcrypto.PrivKey) error {
	r.routing[info.Hash] = *info
	return nil
}

func (r *mockRepo) UploadOrganisation(info *OrganisationInfo, _ bmcrypto.PrivKey, _ proofofwork.ProofOfWork) error {
	r.organisation[info.Hash] = *info
	return nil
}

func (r *mockRepo) DeleteRouting(info *RoutingInfo, _ bmcrypto.PrivKey) error {
	delete(r.routing, info.Hash)
	return nil
}

func (r *mockRepo) DeleteOrganisation(info *OrganisationInfo, _ bmcrypto.PrivKey) error {
	delete(r.organisation, info.Hash)
	return nil
}

func (r *mockRepo) GetConfig() (*ProofOfWorkConfig, error) {
	return &ProofOfWorkConfig{
		ProofOfWork: struct {
			Address      int `json:"address"`
			Organisation int `json:"organisation"`
		}{
			Address:      22,
			Organisation: 22,
		},
	}, nil
}

func (r *mockRepo) CheckReserved(addrorOrgHash hash.Hash) ([]string, error) {
	return []string{"foo.bar"}, nil
}

func (r *mockRepo) DeleteAddress(info *AddressInfo, privKey bmcrypto.PrivKey) error {
	r.deletedAddress[info.Hash] = r.address[info.Hash]
	delete(r.address, info.Hash)

	return nil
}

func (r *mockRepo) UndeleteAddress(info *AddressInfo, privKey bmcrypto.PrivKey) error {
	r.address[info.Hash] = r.deletedAddress[info.Hash]
	delete(r.deletedAddress, info.Hash)

	return nil
}
