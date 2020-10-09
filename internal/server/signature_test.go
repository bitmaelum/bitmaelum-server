package server

import (
	"testing"

	"github.com/bitmaelum/bitmaelum-suite/internal/config"
	"github.com/bitmaelum/bitmaelum-suite/internal/container"
	"github.com/bitmaelum/bitmaelum-suite/internal/message"
	"github.com/bitmaelum/bitmaelum-suite/internal/resolver"
	bmtest "github.com/bitmaelum/bitmaelum-suite/internal/testing"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/stretchr/testify/assert"
)

func Test_signHeader(t *testing.T) {
	setup()

	header := &message.Header{}
	_ = bmtest.ReadJSON("../../testdata/header-001.json", &header)
	assert.Empty(t, header.ServerSignature)
	err := SignHeader(header)
	assert.NoError(t, err)

	assert.Equal(t, "0r2CAu4dc6NNg7GcTVAmMEASrhHpNJdXeW3uS0yjO66FbXOreDeXX70mItF+6rLjTYGnDlZo9Pe5GccgbbcBsib9sQFCOqnHW2a/hsbFo85hyBQufYn7NBP8WEJ/wkJIGkJG3RzLYd/2wet7dVjyLaPhVNI7uMtGsZt2mNpPaUJw8sAX0iu/Dg7HjqY8dS8g6zx+6/Us/IDV34FT8jyNoaCxWU8WKmyTRtAorkiAsHTqNf8aR/uNlmjFNDTvEqIDFWQeKP8eARFg6dncHXOg+7dAbMavo1wvFa1I7C/4Dfp8YBaWSDgwfeRiOzCUQR24svQWMPL0u8THmSy/Ia3qtw==", header.ServerSignature)

	// Already present, don't overwrite
	_ = bmtest.ReadJSON("../../testdata/header-001.json", &header)
	assert.NotEmpty(t, header.ServerSignature)
	header.ServerSignature = "foobar"
	err = SignHeader(header)
	assert.NoError(t, err)

	assert.Equal(t, "foobar", header.ServerSignature)
}

func Test_VerifyHeader(t *testing.T) {
	setup()

	header := &message.Header{}
	_ = bmtest.ReadJSON("../../testdata/header-001.json", &header)
	assert.Empty(t, header.ServerSignature)
	err := SignHeader(header)
	assert.NoError(t, err)
	assert.Equal(t, "0r2CAu4dc6NNg7GcTVAmMEASrhHpNJdXeW3uS0yjO66FbXOreDeXX70mItF+6rLjTYGnDlZo9Pe5GccgbbcBsib9sQFCOqnHW2a/hsbFo85hyBQufYn7NBP8WEJ/wkJIGkJG3RzLYd/2wet7dVjyLaPhVNI7uMtGsZt2mNpPaUJw8sAX0iu/Dg7HjqY8dS8g6zx+6/Us/IDV34FT8jyNoaCxWU8WKmyTRtAorkiAsHTqNf8aR/uNlmjFNDTvEqIDFWQeKP8eARFg6dncHXOg+7dAbMavo1wvFa1I7C/4Dfp8YBaWSDgwfeRiOzCUQR24svQWMPL0u8THmSy/Ia3qtw==", header.ServerSignature)

	// All is ok
	ok := VerifyHeader(*header)
	assert.True(t, ok)

	// Incorrect decoding
	header.ServerSignature = "A"
	ok = VerifyHeader(*header)
	assert.False(t, ok)

	// Empty sig is not ok
	header.ServerSignature = ""
	ok = VerifyHeader(*header)
	assert.False(t, ok)

	// incorrect key
	header.ServerSignature = "Zm9vYmFy"
	ok = VerifyHeader(*header)
	assert.False(t, ok)
}

func setup() {
	// Note: our mail server uses key1
	privKey, pubKey, err := bmtest.ReadTestKey("../../testdata/key-1.json")
	if err != nil {
		panic(err)
	}
	config.Routing = config.RoutingConfig{
		RoutingID:  "12345678",
		PrivateKey: *privKey,
		PublicKey:  *pubKey,
	}

	// Setup container with mock repository for routing
	repo, _ := resolver.NewMockRepository()
	container.SetResolveService(resolver.KeyRetrievalService(repo))

	pow := proofofwork.NewWithoutProof(1, "foobar")
	var (
		ai resolver.AddressInfo
		ri resolver.RoutingInfo
	)

	privKey, pubKey, err = bmtest.ReadTestKey("../../testdata/key-2.json")
	if err != nil {
		panic(err)
	}
	ai = resolver.AddressInfo{
		Hash:        "000000000000000000000000000097026f0daeaec1aeb8351b096637679cf350",
		PublicKey:   *pubKey,
		RoutingID:   "87654321",
		Pow:         pow.String(),
		RoutingInfo: resolver.RoutingInfo{},
	}
	_ = repo.UploadAddress(&ai, *privKey, *pow)

	privKey, pubKey, err = bmtest.ReadTestKey("../../testdata/key-3.json")
	if err != nil {
		panic(err)
	}
	ai = resolver.AddressInfo{
		Hash:        "000000000000000000018f66a0f3591a883f2b9cc3e95a497e7cf9da1071b4cc",
		PublicKey:   *pubKey,
		RoutingID:   "12345678",
		Pow:         pow.String(),
		RoutingInfo: resolver.RoutingInfo{},
	}
	_ = repo.UploadAddress(&ai, *privKey, *pow)

	// Note: our mail server uses key1
	privKey, pubKey, err = bmtest.ReadTestKey("../../testdata/key-1.json")
	if err != nil {
		panic(err)
	}
	ri = resolver.RoutingInfo{
		Hash:      "12345678",
		PublicKey: *pubKey,
		Routing:   "127.0.0.1",
	}
	_ = repo.UploadRouting(&ri, *privKey)
}
