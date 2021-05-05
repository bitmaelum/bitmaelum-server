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

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/stretchr/testify/assert"
)

func TestAPI_GetAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.String(), "/account/c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2/apikey/12345678")
		_, _ = rw.Write([]byte("incorrect data"))
	}))
	defer server.Close()

	api, err := NewAnonymous(server.URL, nil)
	assert.NoError(t, err)

	apiKey, err := api.GetAPIKey(hash.New("foobar"), "12345678")
	assert.Error(t, err)
	assert.Nil(t, apiKey)
}

func TestAPI_GetAPIKey_IncorrectStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.String(), "/account/c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2/apikey/12345678")
		rw.WriteHeader(500)
	}))
	defer server.Close()

	api, err := NewAnonymous(server.URL, nil)
	assert.NoError(t, err)

	apiKey, err := api.GetAPIKey(hash.New("foobar"), "12345678")
	assert.Error(t, err)
	assert.Nil(t, apiKey)
}

func TestAPI_GetAPIKey_ErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.String(), "/account/c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2/apikey/12345678")
		rw.WriteHeader(200)
		_, _ = rw.Write([]byte(`{"error": true, "status":"something happened"}`))
	}))
	defer server.Close()

	api, err := NewAnonymous(server.URL, nil)
	assert.NoError(t, err)

	apiKey, err := api.GetAPIKey(hash.New("foobar"), "12345678")
	assert.EqualError(t, err, "something happened")
	assert.Nil(t, apiKey)
}

func TestAPI_GetAPIKey_Correct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		assert.Equal(t, req.URL.String(), "/account/c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2/apikey/12345678")
		rw.WriteHeader(200)
		_, _ = rw.Write([]byte(`{"key": "12345678", "address_hash":"addresshash", "expires":"2006-01-02T15:04:05Z", "admin": false, "description":"description"}`))
	}))
	defer server.Close()

	api, err := NewAnonymous(server.URL, nil)
	assert.NoError(t, err)

	apiKey, err := api.GetAPIKey(hash.New("foobar"), "12345678")
	assert.NoError(t, err)
	assert.NotNil(t, apiKey)
	assert.Equal(t, apiKey.ID, "12345678")
	assert.Equal(t, apiKey.AddressHash.String(), "addresshash")
	assert.Equal(t, apiKey.Expires.String(), "2006-01-02 15:04:05 +0000 UTC")
	assert.Equal(t, apiKey.Admin, false)
	assert.Equal(t, apiKey.Desc, "description")
}
