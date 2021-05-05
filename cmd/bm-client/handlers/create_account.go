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

package handlers

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/bitmaelum/bitmaelum-suite/cmd/bm-client/internal"
	"github.com/bitmaelum/bitmaelum-suite/cmd/bm-client/internal/container"
	"github.com/bitmaelum/bitmaelum-suite/cmd/bm-client/internal/stepper"
	bminternal "github.com/bitmaelum/bitmaelum-suite/internal"
	"github.com/bitmaelum/bitmaelum-suite/internal/api"
	"github.com/bitmaelum/bitmaelum-suite/internal/resolver"
	"github.com/bitmaelum/bitmaelum-suite/internal/signature"
	"github.com/bitmaelum/bitmaelum-suite/internal/vault"
	"github.com/bitmaelum/bitmaelum-suite/pkg/address"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	pow "github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
)

type args struct {
	Vault        *vault.Vault     // Vault
	AddrStr      string           // Textual representation of the address
	Name         string           // Name of the account
	TokenStr     string           // Additional token for mail server
	KeyType      bmcrypto.KeyType // Type of key to generate
	RedirAddrStr string           // Textual representation of the redirect address
}

type spinnerContext struct {
	Args            args                 // Incoming arguments
	Addr            *address.Address     // Address to create
	AccountInfo     *vault.AccountInfo   // Account info found in the vault
	Proof           *pow.ProofOfWork     // Generated Proof of work
	KeyPair         *bmcrypto.KeyPair    // Generated Keypair
	Reserved        bool                 // True if this address is a reserved address
	ReservedDomains []string             // domains for reserved validation (if any)
	RedirAddr       *address.Address     // Address to redirect to
	Token           *signature.Token     // Information from given token
	AddrObj         resolver.AddressInfo // Address info to send to resolver
}

// CreateAccount creates a new account locally in the vault, stores it on the mail server and pushes the public key to the resolver
func CreateAccount(v *vault.Vault, addrStr, name, tokenStr string, kt bmcrypto.KeyType, redirStr string) {
	s := stepper.New()

	// Setup context for spinner
	spinnerCtx := spinnerContext{
		Args: args{
			Vault:        v,
			AddrStr:      addrStr,
			Name:         name,
			TokenStr:     tokenStr,
			KeyType:      kt,
			RedirAddrStr: redirStr,
		},
	}
	s.Ctx = context.WithValue(s.Ctx, internal.CtxSpinnerContext, &spinnerCtx)

	// Add all the steps from the account creation procedure

	s.AddStep(stepper.Step{
		Title:   fmt.Sprintf("Verifying if address %s%s%s is correct", stepper.AnsiFgYellow, addrStr, stepper.AnsiReset),
		RunFunc: verifyAddress,
	})

	s.AddStep(stepper.Step{
		Title:   "Checking if address is already known in the resolver service",
		RunFunc: checkAddressInResolver,
	})

	s.AddStep(stepper.Step{
		Title:   "Checking if address is a reserved name",
		RunFunc: checkReservedAddress,
	})

	s.AddStep(stepper.Step{
		Title:      "Checking if linked account exists",
		SkipIfFunc: func(s stepper.Stepper) bool { return getAccountContext(s).Args.RedirAddrStr == "" },
		RunFunc:    checkLinkedAddressInResolver,
	})

	s.AddStep(stepper.Step{
		Title:      "Checking if token is valid and extracting data",
		SkipIfFunc: func(s stepper.Stepper) bool { return getAccountContext(s).Args.TokenStr == "" },
		RunFunc:    checkToken,
	})

	s.AddStep(stepper.Step{
		Title:   "Checking if the account is already present in the vault",
		RunFunc: checkAccountInVault,
	})

	s.AddStep(stepper.Step{
		Title:          "Generating your initial keypair",
		DisplaySpinner: true,
		SkipIfFunc:     func(s stepper.Stepper) bool { return getAccountContext(s).AccountInfo != nil },
		RunFunc:        generateKeyPair,
	})

	s.AddStep(stepper.Step{
		Title:          fmt.Sprintf("Doing some work to let people know this is not a fake account, %sthis might take a while%s...", stepper.AnsiFgYellow, stepper.AnsiReset),
		DisplaySpinner: true,
		SkipIfFunc:     func(s stepper.Stepper) bool { return getAccountContext(s).AccountInfo != nil },
		RunFunc:        doProofOfWork,
	})

	s.AddStep(stepper.Step{
		Title:      "Placing your new account into the vault",
		SkipIfFunc: func(s stepper.Stepper) bool { return getAccountContext(s).AccountInfo != nil },
		RunFunc:    addAccountToVault,
	})

	s.AddStep(stepper.Step{
		Title:          "Checking domains for reservation proof",
		RunFunc:        checkReservedDomains,
		SkipIfFunc:     func(s stepper.Stepper) bool { return !getAccountContext(s).Reserved },
		DisplaySpinner: true,
	})

	s.AddStep(stepper.Step{
		Title:          "Sending your account to the server",
		DisplaySpinner: true,
		SkipIfFunc:     func(s stepper.Stepper) bool { return getAccountContext(s).Args.TokenStr == "" },
		RunFunc:        uploadAccountToServer,
	})

	s.AddStep(stepper.Step{
		Title:          "Making your account known to the outside world",
		DisplaySpinner: true,
		RunFunc:        uploadAccountToResolver,
	})

	// Run the stepper
	s.Run()
	if s.Status == stepper.FAILURE {
		fmt.Println("There was an error while creating the account.")
		os.Exit(1)
	}

	kp := getAccountContext(*s).KeyPair
	mnemonic := bminternal.WordWrap(bmcrypto.GetMnemonic(kp), 78)

	fmt.Println(internal.GenerateFromMnemonicTemplate(internal.AccountCreatedTemplate, mnemonic))
}

func verifyAddress(s *stepper.Stepper) stepper.StepResult {
	sc := getAccountContext(*s)

	addr, err := address.NewAddress(sc.Args.AddrStr)
	if err != nil {
		return s.Failure("it seems that this is not a valid address")
	}

	sc.Addr = addr
	sc.AddrObj.Hash = addr.Hash().String()

	return s.Success("")
}

func checkReservedAddress(s *stepper.Stepper) stepper.StepResult {
	addr := getAccountContext(*s).Addr
	if addr == nil {
		return s.Failure("Could not find address")
	}

	ks := container.Instance.GetResolveService()
	domains, _ := ks.CheckReserved(addr.Hash())

	getAccountContext(*s).Reserved = len(domains) > 0
	getAccountContext(*s).ReservedDomains = domains

	if len(domains) > 0 {
		return s.Notice("Yes. DNS verification is needed in order to register this name")
	}

	return s.Success("Not reserved")
}

func checkReservedDomains(s *stepper.Stepper) stepper.StepResult {
	var kp *bmcrypto.KeyPair

	info := getAccountContext(*s).AccountInfo
	if info != nil {
		k := info.GetActiveKey().KeyPair
		kp = &k
	} else {
		kp = getAccountContext(*s).KeyPair
	}

	domains := getAccountContext(*s).ReservedDomains

	for _, domain := range domains {
		// Check domain
		entries, err := net.LookupTXT("_bitmaelum." + domain)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry == kp.PubKey.Fingerprint() {
				return s.Success("found reservation at " + domain)
			}
		}
	}

	msg := internal.GenerateFromFingerprintTemplate(internal.AccountProofTemplate, kp.PubKey.Fingerprint(), domains)
	return s.Failure(msg)
}

func checkLinkedAddressInResolver(s *stepper.Stepper) stepper.StepResult {
	redirAddr, err := address.NewAddress(getAccountContext(*s).Args.RedirAddrStr)
	if err != nil {
		return s.Failure("it seems that the redirect address is not a valid")
	}

	ks := container.Instance.GetResolveService()
	_, err = ks.ResolveAddress(redirAddr.Hash())
	if err != nil {
		return s.Failure("redirect address not found in resolver")
	}

	// Store address into context
	sc := getAccountContext(*s)
	sc.RedirAddr = redirAddr
	sc.AddrObj.RedirHash = redirAddr.Hash().String()

	return s.Success("address is found")
}

func checkAddressInResolver(s *stepper.Stepper) stepper.StepResult {
	ks := container.Instance.GetResolveService()
	_, err := ks.ResolveAddress(getAccountContext(*s).Addr.Hash())

	if err == nil {
		return s.Failure("address already found")
	}

	return s.Success("")
}

func checkToken(s *stepper.Stepper) stepper.StepResult {
	addr := getAccountContext(*s).Addr

	invitationToken, err := signature.ParseInviteToken(getAccountContext(*s).Args.TokenStr)
	if err != nil {
		return s.Failure("it seems that this token is invalid")
	}

	// Check address matches the one in the token
	if invitationToken.AddrHash.String() != addr.Hash().String() {
		return s.Failure(fmt.Sprintf("this token is not for %s", addr.String()))
	}

	sc := getAccountContext(*s)
	sc.Token = invitationToken
	sc.AddrObj.RoutingID = invitationToken.RoutingID

	return s.Success("")
}

func checkAccountInVault(s *stepper.Stepper) stepper.StepResult {
	v := getAccountContext(*s).Args.Vault
	addr := getAccountContext(*s).Addr

	if !v.HasAccount(*addr) {
		return s.Success("not yet found. That's good.")
	}

	info, err := v.GetAccountInfo(*addr)
	if err != nil {
		return s.Failure("found. But error while fetching from the vault.")
	}

	// Update all information with the found settings from the vault
	sc := getAccountContext(*s)
	sc.AccountInfo = info
	sc.Proof = info.Pow
	sc.RedirAddr = info.RedirAddress
	kp := info.GetActiveKey().KeyPair
	sc.KeyPair = &kp
	sc.Addr = info.Address

	sc.AddrObj.Hash = info.Address.Hash().String()
	sc.AddrObj.PublicKey = info.GetActiveKey().PubKey
	sc.AddrObj.RoutingID = info.RoutingID
	sc.AddrObj.Pow = info.Pow.String()

	if info.RedirAddress != nil {
		sc.AddrObj.RedirHash = info.RedirAddress.Hash().String()
	}

	return s.Success("found.")
}

func generateKeyPair(s *stepper.Stepper) stepper.StepResult {
	kt := getAccountContext(*s).Args.KeyType

	kp, err := bmcrypto.GenerateKeypairWithRandomSeed(kt)
	if err != nil {
		return s.Failure(err.Error())
	}

	sc := getAccountContext(*s)
	sc.KeyPair = kp
	sc.AddrObj.PublicKey = kp.PubKey

	return s.Success("")
}

func doProofOfWork(s *stepper.Stepper) stepper.StepResult {
	addr := getAccountContext(*s).Addr

	// Find the number of bits for address creation
	res := container.Instance.GetResolveService()
	resolverCfg := res.GetConfig()

	proof := pow.NewWithoutProof(resolverCfg.ProofOfWork.Address, addr.Hash().String())
	proof.WorkMulticore()

	sc := getAccountContext(*s)
	sc.Proof = proof
	sc.AddrObj.Pow = proof.String()

	return s.Success("")
}

func addAccountToVault(s *stepper.Stepper) stepper.StepResult {
	v := getAccountContext(*s).Args.Vault
	addr := getAccountContext(*s).Addr
	name := getAccountContext(*s).Args.Name
	kp := getAccountContext(*s).KeyPair
	proof := getAccountContext(*s).Proof
	redirAddr := getAccountContext(*s).RedirAddr

	routingID := ""
	if getAccountContext(*s).Token != nil {
		routingID = getAccountContext(*s).Token.RoutingID
	}

	info := &vault.AccountInfo{
		Address:      addr,
		RedirAddress: redirAddr,
		Name:         name,
		Keys: []vault.KeyPair{
			{
				KeyPair: *kp,
				Active:  true,
			},
		},
		Pow:       proof,
		RoutingID: routingID,
	}

	v.AddAccount(*info)

	err := v.Persist()
	if err != nil {
		return s.Failure(fmt.Sprintf("error while saving account into vault: %#v", err))
	}

	return s.Success("")
}

func uploadAccountToServer(s *stepper.Stepper) stepper.StepResult {
	sc := getAccountContext(*s)

	// Fetch routing info
	ks := container.Instance.GetResolveService()
	routingInfo, err := ks.ResolveRouting(sc.Token.RoutingID)
	if err != nil {
		return s.Failure(fmt.Sprintf("cannot find route ID inside the resolver: %#v", err))
	}

	client, err := api.NewAuthenticated(*sc.Addr, sc.KeyPair.PrivKey, routingInfo.Routing, internal.JwtErrorFunc)
	if err != nil {
		return s.Failure("error while authenticating to the API")
	}

	err = client.CreateAccount(*sc.AccountInfo, sc.Args.TokenStr)
	if err != nil {
		if err.Error() == "account already exists" {
			return s.Notice("account already exists on the server.")
		}

		// Other error
		return s.Failure(fmt.Sprintf("error while uploading the account: " + err.Error()))
	}

	return s.Success("")
}

func uploadAccountToResolver(s *stepper.Stepper) stepper.StepResult {
	sc := getAccountContext(*s)

	pk := sc.KeyPair.PrivKey

	ks := container.Instance.GetResolveService()
	err := ks.UploadAddressInfo(*sc.Addr, sc.AddrObj, &pk)
	if err != nil {
		return s.Failure(fmt.Sprintf("error while uploading account to the resolver: %s", err.Error()))
	}

	return s.Success("")
}

// getAccountContext returns the spinner context structure with all information that is communicated between spinner steps
func getAccountContext(s stepper.Stepper) *spinnerContext {
	return s.Ctx.Value(internal.CtxSpinnerContext).(*spinnerContext)
}
