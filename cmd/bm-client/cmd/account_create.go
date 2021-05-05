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
	"github.com/bitmaelum/bitmaelum-suite/cmd/bm-client/handlers"
	"github.com/bitmaelum/bitmaelum-suite/internal/vault"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var createAccountCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates a new account",
	Long: `Creates a new account locally and upload it to a BitMaelum server.

This assumes you have a BitMaelum invitation token for the specific server.`,
	Run: func(cmd *cobra.Command, args []string) {
		v := vault.OpenDefaultVault()

		if *token == "" && *target == "" {
			logrus.Fatal("please specify either --token or --target")
		}

		kt, err := bmcrypto.FindKeyType(*keytype)
		if err != nil {
			logrus.Fatal("incorrect key type")
		}
		handlers.CreateAccount(v, *account, *name, *token, kt, *target)
	},
}

var (
	account *string
	name    *string
	token   *string
	keytype *string
	target  *string
)

func init() {
	accountCmd.AddCommand(createAccountCmd)

	account = createAccountCmd.Flags().String("account", "", "Account to create")
	name = createAccountCmd.Flags().String("name", "", "Your full name")
	token = createAccountCmd.Flags().String("token", "", "Invitation token from server")
	target = createAccountCmd.Flags().String("target", "", "Target address to link to")
	keytype = createAccountCmd.Flags().String("keytype", "ed25519", "Type of key you want to generate (defaults to ed25519)")

	_ = createAccountCmd.MarkFlagRequired("account")
	_ = createAccountCmd.MarkFlagRequired("name")
}
