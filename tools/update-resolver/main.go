package main

import (
	"fmt"
	"os"

	"github.com/bitmaelum/bitmaelum-suite/internal"
	"github.com/bitmaelum/bitmaelum-suite/internal/config"
	"github.com/bitmaelum/bitmaelum-suite/internal/container"
	"github.com/bitmaelum/bitmaelum-suite/internal/vault"
	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	"github.com/sirupsen/logrus"
)

type options struct {
	Config       string `short:"c" long:"config" description:"Path to your configuration file"`
	Password     string `short:"p" long:"password" description:"Vault password" default:""`
	Address      string `short:"a" long:"address" description:"Address" default:""`
	Organisation string `short:"o" long:"organisation" description:"Organisation" default:""`
}

var opts options

func main() {
	internal.ParseOptions(&opts)
	config.LoadClientConfig(opts.Config)

	logrus.SetLevel(logrus.TraceLevel)

	vault.VaultPassword = opts.Password
	v := vault.OpenVault()

	if opts.Address != "" {
		addr, err := address.NewAddress(opts.Address)
		if err != nil {
			logrus.Fatalf("incorrect address")
			os.Exit(1)
		}
		info, err := v.GetAccountInfo(*addr)
		if err != nil {
			logrus.Fatalf("Account '%s' not found in vault", opts.Address)
			os.Exit(1)
		}

		rs := container.GetResolveService()
		err = rs.UploadAddressInfo(*info)
		if err != nil {
			fmt.Printf("Error for account %s: %s\n", info.Address, err)
		}
	}

	if opts.Organisation != "" {
		org := hash.New(opts.Organisation)
		info, _ := v.GetOrganisationInfo(org)
		if info == nil {
			logrus.Fatalf("Organisation '%s' not found in vault", opts.Organisation)
			os.Exit(1)
		}

		rs := container.GetResolveService()
		err := rs.UploadOrganisationInfo(*info)
		if err != nil {
			fmt.Printf("Error for organisation %s: %s\n", info.Addr, err)
		}
	}
}
