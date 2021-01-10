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

package cmd

import (
	"fmt"
	"os"

	"github.com/bitmaelum/bitmaelum-suite/cmd/bm-client/internal/container"
	"github.com/bitmaelum/bitmaelum-suite/internal/vault"
	"github.com/spf13/cobra"
)

var accountKeyAdvertiseCmd = &cobra.Command{
	Use:   "advertise",
	Short: "Advertise new key to the key resolver",
	Run: func(cmd *cobra.Command, args []string) {
		v := vault.OpenDefaultVault()

		info, err := vault.GetAccount(v, *akAccount)
		if err != nil {
			fmt.Println("cannot find account in vault")
			os.Exit(1)
		}

		vkp, err := info.FindKey(*akaKey)
		if err != nil {
			fmt.Println("cannot find key in account")
			os.Exit(1)
		}

		info.SetActiveKey(&vkp.KeyPair)

		// Save vault
		err = v.Persist()
		if err != nil {
			fmt.Println("cannot save vault")
			os.Exit(1)
		}

		ks := container.Instance.GetResolveService()
		err = ks.UploadAddressInfo(*info, "")
		if err != nil {
			fmt.Println("cannot advertise key")
			os.Exit(1)
		}

	},
}

var akaKey *string

func init() {
	accountKeyCmd.AddCommand(accountKeyAdvertiseCmd)

	akaKey = accountKeyAdvertiseCmd.Flags().StringP("key", "k", "", "fingerprint of the key to advertise")

	_ = accountKeyAdvertiseCmd.MarkPersistentFlagRequired("account")
}
