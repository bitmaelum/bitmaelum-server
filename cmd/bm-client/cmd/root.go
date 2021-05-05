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

	"github.com/bitmaelum/bitmaelum-suite/cmd/bm-client/internal"
	bminternal "github.com/bitmaelum/bitmaelum-suite/internal"
	"github.com/bitmaelum/bitmaelum-suite/internal/config"
	"github.com/bitmaelum/bitmaelum-suite/internal/vault"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bm-client",
	Short: "BitMaelum client",
	Long:  `This client allows you to manage accounts, read and compose mail.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// PersistentPreRun will be always called (first). We can actually use the annotations on the
		// command we actually run to configure things.

		// Display logo unless annotations tells us otherwise
		if _, exist := cmd.Annotations["dont_display_logo"]; !exist {
			fmt.Println(bminternal.GetASCIILogo())
		}

		// Load configuration unless annotations tells us otherwise
		if _, exist := cmd.Annotations["dont_load_config"]; !exist {
			config.LoadClientConfig(internal.Opts.Config)

			if internal.Opts.Debug {
				config.Client.Server.DebugHTTP = true
			}

			// Set vault path if not already set
			if vault.VaultPath == "" {
				vault.VaultPath = config.Client.Vault.Path
			}
		}
	},
}

// Execute runs the given command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		fmt.Println("")
		os.Exit(1)
	}
}

func init() {
	// These are not used directly, but are here for --help purposes only. These flags are actually located inside the
	// internal.opts structure
	rootCmd.PersistentFlags().StringP("config", "c", "", "configuration file")
	rootCmd.PersistentFlags().StringP("password", "p", "", "password to unlock your account vault")
	rootCmd.PersistentFlags().StringP("vault", "", "", "custom vault file")
	rootCmd.PersistentFlags().Bool("debug", false, "debug HTTP traffic")
}
