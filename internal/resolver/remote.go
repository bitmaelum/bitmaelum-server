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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/bitmaelum/bitmaelum-suite/internal"
	"github.com/bitmaelum/bitmaelum-suite/internal/organisation"
	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/ernesto-jimenez/httplogger"
	"github.com/sirupsen/logrus"
)

type remoteRepo struct {
	BaseURL string
	client  *http.Client
}

// AddressDownload is a JSON structure we download from a resolver server
type AddressDownload struct {
	Hash      string          `json:"hash"`
	PublicKey bmcrypto.PubKey `json:"public_key"`
	RoutingID string          `json:"routing_id"`
	Serial    uint64          `json:"serial_number"`
}

// RoutingDownload is a JSON structure we download from a resolver server
type RoutingDownload struct {
	Hash      string          `json:"hash"`
	PublicKey bmcrypto.PubKey `json:"public_key"`
	Routing   string          `json:"routing"`
	Serial    uint64          `json:"serial_number"`
}

// OrganisationDownload is a JSON structure we download from a resolver server
type OrganisationDownload struct {
	Hash        string                        `json:"hash"`
	PublicKey   bmcrypto.PubKey               `json:"public_key"`
	Validations []organisation.ValidationType `json:"validations"`
	Serial      uint64                        `json:"serial_number"`
}

// NewRemoteRepository creates new remote resolve repository
func NewRemoteRepository(baseURL string, debug, allowInsecure bool) Repository {
	var transport http.RoundTripper = &http.Transport{
		// Allow insecure and self-signed certificates if so configured
		TLSClientConfig: &tls.Config{InsecureSkipVerify: allowInsecure},
	}

	if debug {
		// Wrap transport in debug logging
		transport = httplogger.NewLoggedTransport(transport, internal.NewHTTPLogger())
	}

	return &remoteRepo{
		BaseURL: baseURL,
		client: &http.Client{
			Transport: transport,
		},
	}
}

// Resolve
func (r *remoteRepo) ResolveAddress(addr hash.Hash) (*AddressInfo, error) {
	kd, err := r.fetchAddress(addr)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Hash:      kd.Hash,
		PublicKey: kd.PublicKey,
		RoutingID: kd.RoutingID,
	}, nil
}

func (r *remoteRepo) ResolveRouting(routingID string) (*RoutingInfo, error) {
	kd, err := r.fetchRouting(routingID)
	if err != nil {
		return nil, err
	}

	return &RoutingInfo{
		Hash:      kd.Hash,
		PublicKey: kd.PublicKey,
		Routing:   kd.Routing,
	}, nil
}

func (r *remoteRepo) ResolveOrganisation(orgHash hash.Hash) (*OrganisationInfo, error) {
	kd, err := r.fetchOrganisation(orgHash)
	if err != nil {
		return nil, err
	}

	return &OrganisationInfo{
		Hash:        kd.Hash,
		PublicKey:   kd.PublicKey,
		Validations: kd.Validations,
	}, nil
}

func (r *remoteRepo) resolve(url string, v interface{}) error {
	response, err := r.client.Get(url)
	if err != nil {
		logrus.Debugf("cannot get response from remote resolver: %s", err)
		return ErrKeyNotFound
	}

	if response.StatusCode == 404 {
		return ErrKeyNotFound
	}

	if response.StatusCode == 200 {
		res, err := ioutil.ReadAll(response.Body)
		if err != nil {
			logrus.Debugf("cannot get body response from remote resolver: %s", err)
			return ErrKeyNotFound
		}

		err = json.Unmarshal(res, v)
		if err != nil {
			logrus.Debugf("cannot unmarshal resolve body: %s", err)
			return ErrKeyNotFound
		}

		return nil
	}

	return ErrKeyNotFound
}

func (r *remoteRepo) UploadAddress(addr address.Address, info *AddressInfo, privKey bmcrypto.PrivKey) error {
	// Fetch the current serial number (if record is present)
	var serial uint64
	kd, err := r.fetchAddress(addr.Hash())
	if err == nil {
		serial = kd.Serial
	}

	data := &map[string]string{
		"user_hash":  addr.LocalHash().String(),
		"org_hash":   addr.OrgHash().String(),
		"public_key": info.PublicKey.String(),
		"routing_id": info.RoutingID,
		"proof":      info.Pow,
		"redir_hash": info.RedirHash,
	}

	url := r.BaseURL + "/address/" + info.Hash
	return r.post(url, data, generateAddressSignature(info, privKey, serial))
}

func (r *remoteRepo) UploadRouting(info *RoutingInfo, privKey bmcrypto.PrivKey) error {
	var serial uint64

	// Fetch the current serial number (if record is present)
	kd, err := r.fetchRouting(info.Hash)
	if err == nil {
		serial = kd.Serial
	}

	data := &map[string]string{
		"public_key": info.PublicKey.String(),
		"routing":    info.Routing,
	}

	url := r.BaseURL + "/routing/" + info.Hash
	return r.post(url, data, generateRoutingSignature(info, privKey, serial))
}

func (r *remoteRepo) UploadOrganisation(info *OrganisationInfo, privKey bmcrypto.PrivKey, proof proofofwork.ProofOfWork) error {
	// Do a prefetch so we can get the current serial number
	org, err := hash.NewFromHash(info.Hash)
	if err != nil {
		return err
	}

	// Fetch the current serial number (if record is present)
	var serial uint64
	kd, err := r.fetchOrganisation(*org)
	if err == nil {
		serial = kd.Serial
	}

	data := &map[string]interface{}{
		"public_key":  info.PublicKey.String(),
		"proof":       proof.String(),
		"validations": info.Validations,
	}

	url := r.BaseURL + "/organisation/" + info.Hash
	return r.post(url, data, generateOrganisationSignature(info, privKey, serial))
}

func (r *remoteRepo) post(url string, v interface{}, sig string) error {
	byteBuf, err := json.Marshal(&v)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(byteBuf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sig)

	logHTTP(req, nil)
	response, err := r.client.Do(req)
	if err != nil {
		logHTTP(response, nil)
		return err
	}

	logHTTP(response, nil)
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		return nil
	}

	return errors.New(string(body))
}

func (r *remoteRepo) DeleteRouting(info *RoutingInfo, privKey bmcrypto.PrivKey) error {
	// Do a prefetch so we can get the current serial number
	kd, err := r.fetchRouting(info.Hash)
	if err != nil {
		return err
	}

	url := r.BaseURL + "/routing/" + info.Hash
	return r.delete(url, generateRoutingSignature(info, privKey, kd.Serial))
}

func (r *remoteRepo) DeleteOrganisation(info *OrganisationInfo, privKey bmcrypto.PrivKey) error {
	// Do a prefetch so we can get the current serial number
	org, err := hash.NewFromHash(info.Hash)
	if err != nil {
		return err
	}
	kd, err := r.fetchOrganisation(*org)
	if err != nil {
		return err
	}

	url := r.BaseURL + "/organisation/" + info.Hash
	return r.delete(url, generateOrganisationSignature(info, privKey, kd.Serial))
}

func (r *remoteRepo) delete(url, sig string) error {
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+sig)
	logHTTP(req, nil)
	response, err := r.client.Do(req)
	if err != nil {
		logHTTP(response, err)
		return err
	}

	logHTTP(response, err)
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		return nil
	}

	return errors.New(string(body))
}

func (r *remoteRepo) fetchAddress(addr hash.Hash) (*AddressDownload, error) {
	url := r.BaseURL + "/address/" + addr.String()

	kd := &AddressDownload{}
	err := r.resolve(url, &kd)
	if err != nil {
		return nil, err
	}

	return kd, nil
}

func (r *remoteRepo) fetchRouting(routingID string) (*RoutingDownload, error) {
	url := r.BaseURL + "/routing/" + routingID

	rd := &RoutingDownload{}
	err := r.resolve(url, &rd)
	if err != nil {
		return nil, err
	}

	return rd, nil
}

func (r *remoteRepo) fetchOrganisation(addr hash.Hash) (*OrganisationDownload, error) {
	url := r.BaseURL + "/organisation/" + addr.String()

	od := &OrganisationDownload{}
	err := r.resolve(url, &od)
	if err != nil {
		return nil, err
	}

	return od, nil
}

func (r *remoteRepo) GetConfig() (*ProofOfWorkConfig, error) {
	url := r.BaseURL + "/config.json"

	cfg := &ProofOfWorkConfig{}
	err := r.resolve(url, &cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (r *remoteRepo) CheckReserved(addrOrOrgHash hash.Hash) ([]string, error) {
	url := r.BaseURL + "/reserved/" + addrOrOrgHash.String()

	var domains = make([]string, 100)
	err := r.resolve(url, &domains)
	if err != nil {
		return nil, err
	}

	return domains, nil
}

func (r *remoteRepo) DeleteAddress(info *AddressInfo, privKey bmcrypto.PrivKey) error {
	// Do a prefetch so we can get the current serial number
	addrHash := hash.Hash(info.Hash)
	kd, err := r.fetchAddress(addrHash)
	if err != nil {
		return err
	}

	url := r.BaseURL + "/address/" + info.Hash + "/delete"
	return r.post(url, nil, generateAddressSignature(info, privKey, kd.Serial))
}

func (r *remoteRepo) UndeleteAddress(info *AddressInfo, privKey bmcrypto.PrivKey) error {
	// Undelete always uses serial 0
	url := r.BaseURL + "/address/" + info.Hash + "/undelete"
	return r.post(url, nil, generateAddressSignature(info, privKey, 0))
}

func logHTTP(v interface{}, err error) {
	if err != nil {
		logrus.Tracef("%s\n\n", err)
		return
	}

	var data []byte

	switch v := v.(type) {
	case *http.Request:
		if v != nil {
			data, err = httputil.DumpRequest(v, true)
		}
	case *http.Response:
		if v != nil {
			data, err = httputil.DumpResponse(v, true)
		}
	}
	if err != nil {
		logrus.Tracef("%s\n\n", err)
		return
	}

	logrus.Tracef("%s\n\n", data)
}
