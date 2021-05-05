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
	"crypto/sha256"
	"encoding/base64"
	"strconv"

	"github.com/bitmaelum/bitmaelum-suite/internal/organisation"
	"github.com/bitmaelum/bitmaelum-suite/internal/vault"
	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

// Service represents a resolver service tied to a specific repository
type Service struct {
	repo         Repository
	routingCache *lru.Cache
	addressCache *lru.Cache
}

// AddressInfo is a structure returned by the external resolver system
type AddressInfo struct {
	Hash        string          `json:"hash"`       // Hash of the email address
	PublicKey   bmcrypto.PubKey `json:"public_key"` // PublicKey of the user
	RoutingID   string          `json:"routing"`    // Routing ID
	RedirHash   string          `json:"redir_hash"` // Routing ID
	Pow         string          `json:"pow"`        // Proof of work
	RoutingInfo RoutingInfo     `json:"_"`          // Don't store
}

// RoutingInfo is a structure returned by the external resolver system
type RoutingInfo struct {
	Hash      string          `json:"hash"`       // Hash / routingID
	PublicKey bmcrypto.PubKey `json:"public_key"` // PublicKey of the user
	Routing   string          `json:"routing"`    // Server where this email address resides
}

// OrganisationInfo is a structure returned by the external resolver system
type OrganisationInfo struct {
	Hash        string                        `json:"hash"`        // Hash of the organisation
	PublicKey   bmcrypto.PubKey               `json:"public_key"`  // PublicKey of the organisation
	Pow         string                        `json:"pow"`         // Proof of work
	Validations []organisation.ValidationType `json:"validations"` // Validations for this organisation
}

// KeyRetrievalService initialises a key retrieval service.
func KeyRetrievalService(repo Repository) *Service {
	c, err := lru.New(64)
	if err != nil {
		c = nil
	}

	a, err := lru.New(64)
	if err != nil {
		a = nil
	}

	return &Service{
		repo:         repo,
		routingCache: c,
		addressCache: a,
	}
}

// ResolveAddress resolves an address.
func (s *Service) ResolveAddress(addr hash.Hash) (*AddressInfo, error) {
	var info *AddressInfo
	// Fetch from cache if available
	if s.addressCache != nil {
		res, ok := s.addressCache.Get(addr.String())
		if ok {
			info = res.(*AddressInfo)
			logrus.Debugf("Resolving cached %s", addr.String())
		}
	}

	if info == nil {
		logrus.Debugf("Resolving address %s", addr.String())
		var err error
		info, err = s.repo.ResolveAddress(addr)
		if err != nil {
			logrus.Debugf("Error while resolving address %s: %s", addr.String(), err)
			return nil, err
		}

		// Store in cache if available
		if s.addressCache != nil {
			_ = s.addressCache.Add(addr.String(), info)
		}
	}

	// Resolve routing info, we often need it
	ri, err := s.repo.ResolveRouting(info.RoutingID)
	if err != nil {
		logrus.Debugf("Error while resolving routing %s for address %s: %s", info.RoutingID, addr.String(), err)
		return nil, err
	}
	info.RoutingInfo = *ri

	return info, err
}

// ClearRoutingCacheEntry will disable using the routing cache.
func (s *Service) ClearRoutingCacheEntry(routingID string) {
	//s.disableCache = false
	s.routingCache.Remove(routingID)
}

// ResolveRouting resolves a route.
func (s *Service) ResolveRouting(routingID string) (*RoutingInfo, error) {
	// Fetch from cache if available
	if s.routingCache != nil {
		info, ok := s.routingCache.Get(routingID)
		if ok {
			logrus.Debugf("Resolving cached %s", routingID)
			return info.(*RoutingInfo), nil
		}
	}

	logrus.Debugf("Resolving %s", routingID)
	info, err := s.repo.ResolveRouting(routingID)
	if err != nil {
		logrus.Debugf("Error while resolving route %s: %s", routingID, err)
		return nil, err
	}

	// Store in cache if available
	if s.routingCache != nil {
		_ = s.routingCache.Add(routingID, info)
	}
	return info, nil
}

// ResolveOrganisation resolves an organisation object.
func (s *Service) ResolveOrganisation(orgHash hash.Hash) (*OrganisationInfo, error) {
	logrus.Debugf("Resolving %s", orgHash)
	info, err := s.repo.ResolveOrganisation(orgHash)
	if err != nil {
		logrus.Debugf("Error while resolving organisation %s: %s", orgHash, err)
	}

	return info, err
}

// UploadAddressInfo uploads resolve information to one (or more) resolvers
func (s *Service) UploadAddressInfo(addr address.Address, addrObj AddressInfo, privkey *bmcrypto.PrivKey) error {
	return s.repo.UploadAddress(addr, &addrObj, *privkey)
}

// UploadRoutingInfo uploads resolve information to one (or more) resolvers
func (s *Service) UploadRoutingInfo(info RoutingInfo, privKey *bmcrypto.PrivKey) error {
	return s.repo.UploadRouting(&info, *privKey)
}

// UploadOrganisationInfo uploads resolve information to one (or more) resolvers
func (s *Service) UploadOrganisationInfo(info vault.OrganisationInfo) error {
	return s.repo.UploadOrganisation(&OrganisationInfo{
		Hash:        hash.New(info.Addr).String(),
		PublicKey:   info.GetActiveKey().PubKey,
		Pow:         info.Pow.String(),
		Validations: info.Validations,
	}, info.GetActiveKey().PrivKey, *info.Pow)
}

// GetConfig returns the configuration from the given repo, or a default configuration on error
func (s *Service) GetConfig() ProofOfWorkConfig {
	cfg, err := s.repo.GetConfig()
	if err == nil {
		return *cfg
	}

	// @TODO: We should not do this i think
	return ProofOfWorkConfig{
		ProofOfWork: struct {
			Address      int `json:"address"`
			Organisation int `json:"organisation"`
		}{
			Address:      20,
			Organisation: 20,
		},
	}
}

// CheckReserved will check if the hash is reserved and returns the domains that can validate the reservation
func (s *Service) CheckReserved(addrOrOrgHash hash.Hash) ([]string, error) {
	return s.repo.CheckReserved(addrOrOrgHash)
}

// generateAddressSignature generates a signature with the accounts private key that can be used for authentication on the resolver
func generateAddressSignature(info *AddressInfo, privKey bmcrypto.PrivKey, serial uint64) string {
	// Generate token
	h := sha256.Sum256([]byte(info.Hash + info.RoutingID + strconv.FormatUint(serial, 10)))
	signature, err := bmcrypto.Sign(privKey, h[:])
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(signature)
}

// generateRoutingSignature generates a signature with the accounts private key that can be used for authentication on the resolver
func generateRoutingSignature(info *RoutingInfo, privKey bmcrypto.PrivKey, serial uint64) string {
	// Generate token
	h := sha256.Sum256([]byte(info.Hash + strconv.FormatUint(serial, 10)))
	signature, err := bmcrypto.Sign(privKey, h[:])
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(signature)
}

// generateOrganisationSignature generates a signature with the accounts private key that can be used for authentication on the resolver
func generateOrganisationSignature(info *OrganisationInfo, privKey bmcrypto.PrivKey, serial uint64) string {
	// Generate token
	h := sha256.Sum256([]byte(info.Hash + strconv.FormatUint(serial, 10)))
	signature, err := bmcrypto.Sign(privKey, h[:])
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(signature)
}

// ActivateAccount will activate an account (public key) on the keyserver. This works only if the key has been previously deactivated and not yet purged
func (s *Service) ActivateAccount(info vault.AccountInfo) error {
	addrInfo := AddressInfo{
		Hash:        info.Address.Hash().String(),
		PublicKey:   info.GetActiveKey().PubKey,
		RoutingID:   info.RoutingID,
		Pow:         info.Pow.String(),
		RoutingInfo: RoutingInfo{},
	}

	return s.repo.UndeleteAddress(&addrInfo, info.GetActiveKey().PrivKey)
}

// DeactivateAccount will deactivate an account (public key) on the keyserver. It can be activated again if the key is not yet purged
func (s *Service) DeactivateAccount(info vault.AccountInfo) error {
	addrInfo := AddressInfo{
		Hash:        info.Address.Hash().String(),
		PublicKey:   info.GetActiveKey().PubKey,
		RoutingID:   info.RoutingID,
		Pow:         info.Pow.String(),
		RoutingInfo: RoutingInfo{},
	}

	return s.repo.DeleteAddress(&addrInfo, info.GetActiveKey().PrivKey)
}
