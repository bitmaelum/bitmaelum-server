package config

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/google/uuid"
	"github.com/spf13/afero"
)

// Routing holds routing configuration for the mail server
type Routing struct {
	RoutingID  string           `json:"routing_id"`
	PrivateKey bmcrypto.PrivKey `json:"private_key"`
	PublicKey  bmcrypto.PubKey  `json:"public_key"`
}

// ReadRouting will read the routing file and merge it into the server configuration
func ReadRouting(p string) error {
	f, err := fs.Open(p)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	Server.Routing = &Routing{}
	err = json.Unmarshal(data, Server.Routing)
	if err != nil {
		return err
	}

	return nil
}

// SaveRouting will save the routing into a file. It will overwrite if exists
func SaveRouting(p string, routing *Routing) error {
	data, err := json.MarshalIndent(routing, "", "  ")
	if err != nil {
		return err
	}

	err = fs.MkdirAll(filepath.Dir(p), 0755)
	if err != nil {
		return err
	}

	return afero.WriteFile(fs, p, data, 0600)
}

// Generate generates a new routing structure
func Generate() (*Routing, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	privKey, pubKey, err := bmcrypto.GenerateKeyPair(bmcrypto.KeyTypeRSA)
	if err != nil {
		return nil, err
	}

	return &Routing{
		RoutingID:  hash.New(id.String()).String(),
		PrivateKey: *privKey,
		PublicKey:  *pubKey,
	}, nil
}
