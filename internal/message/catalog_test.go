package message

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bitmaelum/bitmaelum-suite/internal"
	bmtest "github.com/bitmaelum/bitmaelum-suite/internal/testing"
	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestCatalog_NewCatalog(t *testing.T) {
	c := genCatalog()

	assert.Equal(t, "john!", c.From.Address)
	assert.False(t, c.CreatedAt.Before(time.Now().Add(-1*time.Second)))
	assert.Equal(t, "", c.Subject)
}

func TestCatalog_AddFlags(t *testing.T) {
	c := genCatalog()

	assert.Len(t, c.Flags, 0)
	c.AddFlags("foo")
	assert.Len(t, c.Flags, 1)

	c.AddFlags("bar", "baz")
	assert.Len(t, c.Flags, 3)

	// @TODO: Adding an existing flag should skip it
	c.AddFlags("bar")
	assert.Len(t, c.Flags, 4)
}

func TestCatalog_AddLabels(t *testing.T) {
	c := genCatalog()

	assert.Len(t, c.Labels, 0)
	c.AddLabels("foo")
	assert.Len(t, c.Labels, 1)

	c.AddLabels("bar", "baz")
	assert.Len(t, c.Labels, 3)

	// @TODO: Adding an existing Labels should skip it
	c.AddLabels("bar")
	assert.Len(t, c.Labels, 4)
}

func TestCatalog_SetToAddress(t *testing.T) {
	c := genCatalog()

	assert.Empty(t, c.To)

	addr, err := address.NewAddress("jane!")
	assert.NoError(t, err)
	c.SetToAddress(*addr, "Jane Doe")
	assert.Equal(t, "jane!", c.To.Address)
	assert.Equal(t, "Jane Doe", c.To.Name)
}

func TestCatalog_AddAttachment(t *testing.T) {
	c := genCatalog()

	// Setup afero
	fs = afero.NewMemMapFs()

	// 1 px gif
	buf1, err := base64.StdEncoding.DecodeString("R0lGODlhAQABAAAAACH5BAEAAAAALAAAAAABAAEAAAI=")
	assert.NoError(t, err)
	_ = afero.WriteFile(fs, "/dir/image.png", buf1, 0644)

	buf2 := make([]byte, 2048)
	_, _ = io.ReadFull(rand.Reader, buf2)
	_ = afero.WriteFile(fs, "/dir/largerfile.dat", buf2, 0644)

	// Nothing attached
	assert.Len(t, c.Attachments, 0)

	// Small gif attached
	entry := Attachment{
		Path:   "/dir/image.png",
		Reader: bytes.NewReader(buf1[:]),
	}
	err = c.AddAttachment(entry)
	assert.NoError(t, err)

	assert.Len(t, c.Attachments, 1)
	assert.Equal(t, "image.png", c.Attachments[0].FileName)
	assert.NotEmpty(t, c.Attachments[0].IV)
	assert.NotEmpty(t, c.Attachments[0].Key)
	assert.Equal(t, "image/gif", c.Attachments[0].MimeType)
	assert.NotNil(t, c.Attachments[0].Reader)
	assert.Equal(t, uint64(32), c.Attachments[0].Size)

	// larger blob attached
	entry = Attachment{
		Path:   "/dir/largerfile.dat",
		Reader: bytes.NewReader(buf2[:]),
	}
	err = c.AddAttachment(entry)
	assert.NoError(t, err)

	assert.Len(t, c.Attachments, 2)
	assert.Equal(t, "largerfile.dat", c.Attachments[1].FileName)
	assert.NotEmpty(t, c.Attachments[1].IV)
	assert.NotEmpty(t, c.Attachments[1].Key)
	assert.NotNil(t, c.Attachments[1].Reader)
	assert.Equal(t, uint64(2048), c.Attachments[1].Size)
	assert.Equal(t, "zlib", c.Attachments[1].Compression)
}

func TestCatalog_AddBlock(t *testing.T) {
	c := genCatalog()

	// // Setup afero
	// fs = afero.NewMemMapFs()
	//
	// // 1 px gif
	// buf1, err := base64.StdEncoding.DecodeString("R0lGODlhAQABAAAAACH5BAEAAAAALAAAAAABAAEAAAI=")
	// assert.NoError(t, err)
	// _ = afero.WriteFile(fs, "/dir/image.png", buf1, 0644)
	//
	// _ = afero.WriteFile(fs, "/dir/largerfile.dat", buf2, 0644)

	// Nothing attached
	assert.Len(t, c.Blocks, 0)

	// Small gif attached
	entry := Block{
		Type:   "text",
		Size:   27,
		Reader: strings.NewReader("this is a block of 32 bytes"),
	}
	err := c.AddBlock(entry)
	assert.NoError(t, err)

	assert.Len(t, c.Blocks, 1)
	assert.Equal(t, "", c.Blocks[0].Compression)
	assert.NotEmpty(t, c.Blocks[0].Key)
	assert.NotEmpty(t, c.Blocks[0].IV)
	assert.NotEmpty(t, c.Blocks[0].ID)
	assert.Equal(t, "text", c.Blocks[0].Type)
	assert.Equal(t, uint64(27), c.Blocks[0].Size)

	// larger content
	buf2 := make([]byte, 2048)
	_, _ = io.ReadFull(rand.Reader, buf2)

	entry = Block{
		Type:   "html",
		Size:   2048,
		Reader: bytes.NewReader(buf2[:]),
	}
	err = c.AddBlock(entry)
	assert.NoError(t, err)

	assert.Len(t, c.Blocks, 2)
	assert.Equal(t, "zlib", c.Blocks[1].Compression)
	assert.NotEmpty(t, c.Blocks[1].Key)
	assert.NotEmpty(t, c.Blocks[1].IV)
	assert.NotEmpty(t, c.Blocks[1].ID)
	assert.Equal(t, "html", c.Blocks[1].Type)
	assert.Equal(t, uint64(2048), c.Blocks[1].Size)

	assert.True(t, c.HasBlock("html"))
	assert.True(t, c.HasBlock("text"))
	assert.False(t, c.HasBlock("somethingelse"))

	assert.Equal(t, "text", c.GetFirstBlock().Type)

	blck, _ := c.GetBlock("text")
	assert.Equal(t, c.Blocks[0].ID, blck.ID)

	blck, _ = c.GetBlock("html")
	assert.Equal(t, c.Blocks[1].ID, blck.ID)

	blck, err = c.GetBlock("does-not-exist")
	assert.Error(t, err)
	assert.Nil(t, blck)
}

func genCatalog() *Catalog {
	privKey, pubKey, _ := bmtest.ReadTestKey("../../testdata/key-1.json")

	info := internal.AccountInfo{
		Default:   true,
		Address:   "john!",
		Name:      "John Doe",
		Settings:  nil,
		PrivKey:   *privKey,
		PubKey:    *pubKey,
		Pow:       &proofofwork.ProofOfWork{},
		RoutingID: "",
	}
	return NewCatalog(&info)
}
