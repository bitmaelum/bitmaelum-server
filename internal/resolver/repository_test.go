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
	"testing"

	bmtest "github.com/bitmaelum/bitmaelum-suite/internal/testing"
	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/stretchr/testify/assert"
)

func testRepoAddress(t *testing.T, repo AddressRepository) {
	a, err := address.NewAddress("example!")
	assert.NoError(t, err)

	addr, err := repo.ResolveAddress(a.Hash())
	assert.Errorf(t, err, "sql: no rows in result set")
	assert.Nil(t, addr)

	privKey, pubKey, _ := bmtest.ReadTestKey("../../testdata/key-1.json")
	pow := proofofwork.New(22, "foobar", 1234)

	ai := AddressInfo{
		Hash:      a.Hash().String(),
		PublicKey: *pubKey,
		RoutingID: "1234",
		Pow:       pow.String(),
		RoutingInfo: RoutingInfo{
			Hash:      "1234",
			PublicKey: *pubKey,
			Routing:   "127.0.0.1",
		},
	}

	err = repo.UploadAddress(*a, &ai, *privKey)
	assert.NoError(t, err)

	addr, err = repo.ResolveAddress(a.Hash())
	assert.NoError(t, err)
	assert.NotNil(t, addr)
	assert.Equal(t, "2244643da7475120bf84d744435d15ea297c36ca165ea0baaa69ec818d0e952f", addr.Hash)

	err = repo.DeleteAddress(&ai, *privKey)
	assert.NoError(t, err)

	addr, err = repo.ResolveAddress(a.Hash())
	assert.Errorf(t, err, "sql: no rows in result set")
	assert.Nil(t, addr)
}

func testRepoRouting(t *testing.T, repo RoutingRepository) {
	r, err := repo.ResolveRouting("12345678")
	assert.Errorf(t, err, "sql: no rows in result set")
	assert.Nil(t, r)

	privKey, pubKey, _ := bmtest.ReadTestKey("../../testdata/key-1.json")

	ri := RoutingInfo{
		Hash:      "12345678",
		PublicKey: *pubKey,
		Routing:   "127.0.0.1",
	}

	err = repo.UploadRouting(&ri, *privKey)
	assert.NoError(t, err)

	r, err = repo.ResolveRouting("12345678")
	assert.NoError(t, err)
	assert.Equal(t, "12345678", r.Hash)

	err = repo.DeleteRouting(&ri, *privKey)
	assert.NoError(t, err)

	r, err = repo.ResolveRouting("12345678")
	assert.Errorf(t, err, "sql: no rows in result set")
	assert.Nil(t, r)
}

func testRepoOrganisation(t *testing.T, repo OrganisationRepository) {
	org := hash.New("acme")

	r, err := repo.ResolveOrganisation(org)
	assert.Errorf(t, err, "sql: no rows in result set")
	assert.Nil(t, r)

	privKey, pubKey, _ := bmtest.ReadTestKey("../../testdata/key-1.json")
	pow := proofofwork.New(22, "foo", 1)

	oi := OrganisationInfo{
		Hash:        org.String(),
		PublicKey:   *pubKey,
		Pow:         pow.String(),
		Validations: nil,
	}

	err = repo.UploadOrganisation(&oi, *privKey, *pow)
	assert.NoError(t, err)

	r, err = repo.ResolveOrganisation(org)
	assert.NoError(t, err)
	assert.Equal(t, org.String(), r.Hash)

	err = repo.DeleteOrganisation(&oi, *privKey)
	assert.NoError(t, err)

	r, err = repo.ResolveOrganisation(org)
	assert.Errorf(t, err, "sql: no rows in result set")
	assert.Nil(t, r)
}
