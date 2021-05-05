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

package main

import (
	"fmt"
	"os"

	"github.com/bitmaelum/bitmaelum-suite/internal"
	"github.com/bitmaelum/bitmaelum-suite/internal/config"
	"github.com/bitmaelum/bitmaelum-suite/internal/container"
	"github.com/bitmaelum/bitmaelum-suite/internal/resolver"
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

	v, err := vault.Open(config.Client.Vault.Path, opts.Password)
	if err != nil {
		fmt.Println("cannot open vault")
		os.Exit(1)
	}

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

		addrObj := &resolver.AddressInfo{
			Hash:      info.Address.Hash().String(),
			PublicKey: info.GetActiveKey().PubKey,
			RoutingID: info.RoutingID,
			RedirHash: info.RedirAddress.Hash().String(),
			Pow:       info.Pow.String(),
		}

		pk := info.GetActiveKey().PrivKey

		rs := container.Instance.GetResolveService()
		err = rs.UploadAddressInfo(*info.Address, *addrObj, &pk)
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

		rs := container.Instance.GetResolveService()
		err := rs.UploadOrganisationInfo(*info)
		if err != nil {
			fmt.Printf("Error for organisation %s: %s\n", info.Addr, err)
		}
	}
}
