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
	"github.com/bitmaelum/bitmaelum-suite/internal"
	"github.com/bitmaelum/bitmaelum-suite/internal/resolver"
	"github.com/bitmaelum/bitmaelum-suite/internal/vault"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var accountKeyGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new account key",
	Long: `Generate a new key into your account. The keytype (--keytype, -k) can be either one of the following:
	
  ed25519   ED25519 elliptic curve
  rsa       RSA 2048 bit 
  rsa4096   RSA 4096 bit 

`, Run: func(cmd *cobra.Command, args []string) {
		v := vault.OpenDefaultVault()

		info, err := vault.GetAccount(v, *akAccount)
		if err != nil {
			fmt.Println("cannot find account in vault")
			os.Exit(1)
		}

		kt, err := bmcrypto.FindKeyType(*keyType)
		if err != nil {
			logrus.Fatal(err)
		}

		kp, err := bmcrypto.GenerateKeypairWithRandomSeed(kt)
		if err != nil {
			logrus.Fatal(err)
		}

		info.Keys = append(info.Keys, vault.KeyPair{
			KeyPair: *kp,
			Active:  false,
		})

		fmt.Print(`
*****************************************************************************
!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORT
*****************************************************************************

We have generated a private key which allows you to control your account. 
If, for any reason, you lose this key, you will need to use the following 
words in order to recreate the key:

`)
		fmt.Print(internal.WordWrap(bmcrypto.GetMnemonic(kp), 78))
		fmt.Print(`

Write these words down and store them in a secure environment. They are the 
ONLY way to recover your private key in case you lose it.

WITHOUT THESE WORDS, ALL ACCESS TO YOUR ACCOUNT IS LOST!


`)

		// Upload the new key to the server
		if *advertise {
			info.SetActiveKey(kp)

			addrObj := &resolver.AddressInfo{
				Hash:      info.Address.Hash().String(),
				PublicKey: info.GetActiveKey().PubKey,
				RoutingID: info.RoutingID,
				RedirHash: info.RedirAddress.Hash().String(),
				Pow:       info.Pow.String(),
			}

			pk := info.GetActiveKey().PrivKey

			ks := container.Instance.GetResolveService()
			err = ks.UploadAddressInfo(*info.Address, *addrObj, &pk)
		}

		// Error or we didn't advertise
		if err != nil || !*advertise {
			fmt.Printf("Note: your key is not yet advertised. To make sure others use your key, please run:\n\n   bm-client account key advertise --account %s --key %s`\n", info.Address, kp.FingerPrint)
		}

		// Save vault
		err = v.Persist()
		if err != nil {
			fmt.Println("cannot save vault")
			os.Exit(1)
		}
	},
}

var (
	keyType   *string
	advertise *bool
)

func init() {
	accountKeyCmd.AddCommand(accountKeyGenerateCmd)

	keyType = accountKeyGenerateCmd.Flags().StringP("keytype", "k", "ed25519", "The key type (defaults to ed25519)")
	advertise = accountKeyGenerateCmd.Flags().BoolP("advertise", "a", false, "Automatically advertise the key")
}
