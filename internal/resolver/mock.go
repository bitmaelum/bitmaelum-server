package resolver

import (
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
)

type mockRepo struct {
	address      map[string]AddressInfo
	routing      map[string]RoutingInfo
	organisation map[string]OrganisationInfo
}

// NewMockRepository creates a simple mock repository for testing purposes
func NewMockRepository() (Repository, error) {
	r := &mockRepo{}

	r.address = make(map[string]AddressInfo)
	r.routing = make(map[string]RoutingInfo)
	r.organisation = make(map[string]OrganisationInfo)
	return r, nil

}

func (r *mockRepo) ResolveAddress(addr hash.Hash) (*AddressInfo, error) {
	if ai, ok := r.address[addr.String()]; ok {
		return &ai, nil
	}

	return nil, errKeyNotFound
}

func (r *mockRepo) ResolveRouting(routingID string) (*RoutingInfo, error) {
	if ri, ok := r.routing[routingID]; ok {
		return &ri, nil
	}

	return nil, errKeyNotFound
}

func (r *mockRepo) ResolveOrganisation(orgHash hash.Hash) (*OrganisationInfo, error) {
	if oi, ok := r.organisation[orgHash.String()]; ok {
		return &oi, nil
	}

	return nil, errKeyNotFound
}

func (r *mockRepo) UploadAddress(info *AddressInfo, _ bmcrypto.PrivKey, _ proofofwork.ProofOfWork) error {
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

func (r *mockRepo) DeleteAddress(info *AddressInfo, _ bmcrypto.PrivKey) error {
	delete(r.address, info.Hash)
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
