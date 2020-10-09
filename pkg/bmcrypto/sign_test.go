package bmcrypto

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Mock reader so we deterministic signature
type dummyReader struct{}

var (
	signMessage = []byte("b2d31086f098254d32314438a863e61e")
)

func (d *dummyReader) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 1
	}
	return len(b), nil
}

func TestSignRSA(t *testing.T) {
	randReader = &dummyReader{}

	data, err := ioutil.ReadFile("../../testdata/privkey.rsa")
	assert.NoError(t, err)
	privKey, err := NewPrivKey(string(data))
	assert.NoError(t, err)
	data, err = ioutil.ReadFile("../../testdata/pubkey.rsa")
	assert.NoError(t, err)
	pubKey, err := NewPubKey(string(data))
	assert.NoError(t, err)

	sig, err := Sign(*privKey, signMessage)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x74, 0xc7, 0x7, 0x9a, 0x72, 0x7e, 0x1, 0xf2, 0xac, 0xa1, 0x56, 0x4e, 0x95, 0x97, 0x41, 0x60, 0xb6, 0x23, 0x13, 0x16, 0xda, 0x6b, 0xa1, 0xe1, 0x5d, 0x52, 0x37, 0xe2, 0x8b, 0xac, 0x55, 0x9, 0xac, 0xbe, 0x2d, 0xbd, 0x2f, 0xd4, 0xae, 0xdb, 0xd4, 0xf, 0xd6, 0xee, 0xfe, 0x75, 0x86, 0xf5, 0xca, 0xa5, 0x2f, 0x6f, 0xba, 0x24, 0xdb, 0x8a, 0xb3, 0xd5, 0x81, 0xeb, 0xbf, 0xe6, 0x71, 0xe4, 0xb1, 0x1b, 0x6e, 0x8a, 0x6e, 0x72, 0x6c, 0x5d, 0x27, 0x57, 0x24, 0xb7, 0x4e, 0xa5, 0xb1, 0xf5, 0x0, 0x84, 0xad, 0x99, 0x82, 0x88, 0xb7, 0x1a, 0x2a, 0x7e, 0xcc, 0x61, 0x6f, 0x77, 0x58, 0x3d, 0xda, 0x9, 0x18, 0xb, 0xfc, 0x3, 0x22, 0xf5, 0x3, 0x96, 0x44, 0xf5, 0x10, 0xf9, 0x20, 0xfc, 0x27, 0xb7, 0x47, 0xfe, 0xf7, 0x56, 0x4b, 0x98, 0x5c, 0xce, 0x13, 0xed, 0x11, 0x74, 0x8e, 0x4e}, sig)

	res, err := Verify(*pubKey, signMessage, sig)
	assert.NoError(t, err)
	assert.True(t, res)

	sig[0] ^= 0x80
	res, _ = Verify(*pubKey, signMessage, sig)
	assert.False(t, res)
}

func TestSignECDSA(t *testing.T) {
	randReader = &dummyReader{}

	data, err := ioutil.ReadFile("../../testdata/privkey.ecdsa")
	assert.NoError(t, err)
	privKey, err := NewPrivKey(string(data))
	assert.NoError(t, err)
	data, err = ioutil.ReadFile("../../testdata/pubkey.ecdsa")
	assert.NoError(t, err)
	pubKey, err := NewPubKey(string(data))
	assert.NoError(t, err)

	sig, err := Sign(*privKey, signMessage)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x65, 0x2, 0x30, 0x2e, 0x0, 0x2b, 0x6e, 0x28, 0xb6, 0x9f, 0x2a, 0xb7, 0x80, 0x0, 0x76, 0xe2, 0x4b, 0x29, 0xb2, 0x46, 0xad, 0x88, 0x5e, 0x24, 0x51, 0xd6, 0xe7, 0xba, 0x80, 0x57, 0x19, 0x33, 0xbb, 0x1, 0x2d, 0x85, 0xd6, 0x3c, 0x10, 0xff, 0x9d, 0x52, 0x37, 0x73, 0x9a, 0xba, 0xa6, 0x5e, 0xd9, 0x3c, 0x81, 0x2, 0x31, 0x0, 0xd0, 0xd0, 0x3a, 0xc0, 0xd1, 0x54, 0x2e, 0x6b, 0x9f, 0xa1, 0x33, 0x78, 0x6a, 0x4f, 0x8e, 0x1, 0x8e, 0xed, 0x8, 0xd7, 0x9e, 0xed, 0xd7, 0x53, 0x56, 0xa7, 0x3b, 0xe5, 0xd7, 0x4b, 0xfa, 0xb5, 0xad, 0xa2, 0x7f, 0x4f, 0x91, 0x4, 0x65, 0x7a, 0xa3, 0x98, 0xc8, 0xcd, 0x1, 0xe6, 0x2d, 0x39}, sig)

	res, err := Verify(*pubKey, signMessage, sig)
	assert.NoError(t, err)
	assert.True(t, res)

	sig[0] ^= 0x80
	res, _ = Verify(*pubKey, signMessage, sig)
	assert.False(t, res)
}

func TestSignED25519(t *testing.T) {
	randReader = &dummyReader{}

	data, err := ioutil.ReadFile("../../testdata/privkey.ed25519")
	assert.NoError(t, err)
	privKey, err := NewPrivKey(string(data))
	assert.NoError(t, err)
	data, err = ioutil.ReadFile("../../testdata/pubkey.ed25519")
	assert.NoError(t, err)
	pubKey, err := NewPubKey(string(data))
	assert.NoError(t, err)

	sig, err := Sign(*privKey, signMessage)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x41, 0x5c, 0x11, 0xb4, 0x4a, 0x3a, 0xbc, 0x62, 0x6f, 0xe, 0x21, 0x7d, 0xd9, 0xee, 0x3e, 0x4a, 0x52, 0x9f, 0x2, 0xe5, 0x3f, 0xdb, 0xd6, 0xe7, 0xb3, 0xdd, 0xb2, 0x62, 0x66, 0x91, 0x42, 0x43, 0x4c, 0xbe, 0x7f, 0x2c, 0x8d, 0x48, 0xf7, 0xe2, 0x9a, 0xc2, 0xe5, 0x38, 0xc4, 0xc3, 0xd2, 0x2d, 0xcc, 0x60, 0xf5, 0x25, 0xec, 0xa9, 0x9, 0xb1, 0xa6, 0x5f, 0xe1, 0xfa, 0xe4, 0x14, 0xd0, 0x5}, sig)

	res, err := Verify(*pubKey, signMessage, sig)
	assert.NoError(t, err)
	assert.True(t, res)

	sig[0] ^= 0x80
	res, _ = Verify(*pubKey, signMessage, sig)
	assert.False(t, res)
}

func TestSignErr(t *testing.T) {
	data, err := ioutil.ReadFile("../../testdata/privkey.ed25519")
	assert.NoError(t, err)
	privKey, err := NewPrivKey(string(data))
	assert.NoError(t, err)

	data, err = ioutil.ReadFile("../../testdata/pubkey.ed25519")
	assert.NoError(t, err)
	pubKey, err := NewPubKey(string(data))
	assert.NoError(t, err)

	privKey.Type = "fooooobar-notexist"
	sig, err := Sign(*privKey, []byte("message"))
	assert.Errorf(t, err, "unknown key type for signing")
	assert.Nil(t, sig)

	pubKey.Type = "foooobar-notexist"
	ok, err := Verify(*pubKey, []byte{}, []byte{})
	assert.Errorf(t, err, "unknown key type for signing")
	assert.False(t, ok)
}
