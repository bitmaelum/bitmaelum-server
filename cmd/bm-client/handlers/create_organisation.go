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
	"github.com/bitmaelum/bitmaelum-suite/internal/organisation"
	"github.com/bitmaelum/bitmaelum-suite/internal/vault"
	"github.com/bitmaelum/bitmaelum-suite/pkg/bmcrypto"
	"github.com/bitmaelum/bitmaelum-suite/pkg/hash"
	pow "github.com/bitmaelum/bitmaelum-suite/pkg/proofofwork"
)

type orgArgs struct {
	Vault       *vault.Vault     // Vault
	OrgAddrStr  string           // Textual representation of the address
	OrgAddrHash hash.Hash        // Hash representation of the address
	Name        string           // Name of the account
	TokenStr    string           // Additional token for mail server
	KeyType     bmcrypto.KeyType // Type of key to generate
	Validations []string         // textual representation of validations
}

type orgSpinnerContext struct {
	Args            orgArgs                       // Incoming arguments
	Reserved        bool                          // True if this address is a reserved address
	ReservedDomains []string                      // domains for reserved validation (if any)
	Organisation    *vault.OrganisationInfo       // Organisation info
	KeyPair         *bmcrypto.KeyPair             // Generated key pair (if generated)
	Validations     []organisation.ValidationType // Validations
	Proof           *pow.ProofOfWork              // proof-of-work (if generated)
}

// CreateOrganisation creates a new organisation locally in the vault and pushes the public key to the resolver
func CreateOrganisation(v *vault.Vault, orgAddr, fullName string, orgValidations []string, kt bmcrypto.KeyType) {
	s := stepper.New()

	// Setup context for spinner
	spinnerCtx := orgSpinnerContext{
		Args: orgArgs{
			Vault:       v,
			KeyType:     kt,
			Name:        fullName,
			Validations: orgValidations,
			OrgAddrStr:  orgAddr,
			OrgAddrHash: hash.New(orgAddr),
		},
	}
	s.Ctx = context.WithValue(s.Ctx, internal.CtxSpinnerContext, spinnerCtx)

	// Add all the steps from the account creation procedure

	s.AddStep(stepper.Step{
		Title:   "Checking if organisation is already known in the resolver service",
		RunFunc: checkOrganisationInResolver,
	})

	s.AddStep(stepper.Step{
		Title:   "Checking if address is a reserved name",
		RunFunc: checkOrganisationReservedAddress,
	})

	s.AddStep(stepper.Step{
		Title:          "Checking if validations are correct",
		DisplaySpinner: true,
		RunFunc:        checkValidations,
	})

	s.AddStep(stepper.Step{
		Title:   "Checking if the organisation is already present in the vault",
		RunFunc: checkOrganisationInVault,
	})

	s.AddStep(stepper.Step{
		Title:          "Generating organisation public/private keypair",
		DisplaySpinner: true,
		SkipIfFunc:     func(s stepper.Stepper) bool { return getOrganisationContext(s).Organisation == nil },
		RunFunc:        generateOrganisationKeyPair,
	})

	s.AddStep(stepper.Step{
		Title:          fmt.Sprintf("Doing some work to let people know this is not a fake account, %sthis might take a while%s...", stepper.AnsiFgYellow, stepper.AnsiReset),
		DisplaySpinner: true,
		SkipIfFunc:     func(s stepper.Stepper) bool { return getOrganisationContext(s).Organisation == nil },
		RunFunc:        doProofOfWorkOrg,
	})

	s.AddStep(stepper.Step{
		Title:      "Placing your new organisation into the vault",
		SkipIfFunc: func(s stepper.Stepper) bool { return getOrganisationContext(s).Organisation == nil },
		RunFunc:    addOrganisationToVault,
	})

	s.AddStep(stepper.Step{
		Title:          "Checking domains for reservation proof",
		RunFunc:        checkOrganisationReservedDomains,
		SkipIfFunc:     func(s stepper.Stepper) bool { return !getOrganisationContext(s).Reserved },
		DisplaySpinner: true,
	})

	s.AddStep(stepper.Step{
		Title:          "Making your organisation known to the outside world",
		DisplaySpinner: true,
		RunFunc:        uploadOrganisationToResolver,
	})

	// Run the stepper
	s.Run()
	if s.Status == stepper.FAILURE {
		fmt.Println("There was an error while creating the organisation.")
		os.Exit(1)
	}

	kp := getOrganisationContext(*s).Organisation.GetActiveKey().KeyPair
	mnemonic := bminternal.WordWrap(bmcrypto.GetMnemonic(&kp), 78)

	fmt.Println(internal.GenerateFromMnemonicTemplate(internal.OrganisationCreatedTemplate, mnemonic))
}

func checkOrganisationInVault(s *stepper.Stepper) stepper.StepResult {
	v := getOrganisationContext(*s).Args.Vault
	orgHash := getOrganisationContext(*s).Args.OrgAddrHash

	if !v.HasOrganisation(orgHash) {
		return s.Success("not found. That's good.")
	}

	info, err := v.GetOrganisationInfo(orgHash)
	if err != nil {
		return s.Failure("found. But error while fetching from the vault.")
	}

	sc := getOrganisationContext(*s)
	sc.Organisation = info

	return s.Success("found. That's odd, but let's continue...")
}

func checkOrganisationInResolver(s *stepper.Stepper) stepper.StepResult {
	orgHash := getOrganisationContext(*s).Args.OrgAddrHash

	ks := container.Instance.GetResolveService()
	_, err := ks.ResolveOrganisation(orgHash)

	if err == nil {
		return s.Failure("organisation already found")
	}

	return s.Success("")
}

func checkValidations(s *stepper.Stepper) stepper.StepResult {
	arr := getOrganisationContext(*s).Args.Validations
	validations, err := organisation.NewValidationTypeFromStringArray(arr)
	if err != nil {
		return s.Failure("validation failed")
	}

	sc := getOrganisationContext(*s)
	sc.Validations = validations

	return s.Success("")
}

func doProofOfWorkOrg(s *stepper.Stepper) stepper.StepResult {
	orgHash := getOrganisationContext(*s).Args.OrgAddrHash

	// Find the number of bits for address creation
	res := container.Instance.GetResolveService()
	resolverCfg := res.GetConfig()

	proof := pow.NewWithoutProof(resolverCfg.ProofOfWork.Organisation, orgHash.String())
	proof.WorkMulticore()

	sc := getOrganisationContext(*s)
	sc.Proof = proof

	return s.Success("")
}

func generateOrganisationKeyPair(s *stepper.Stepper) stepper.StepResult {
	kt := getOrganisationContext(*s).Args.KeyType
	kp, err := bmcrypto.GenerateKeypairWithRandomSeed(kt)
	if err != nil {
		return s.Failure(err.Error())
	}

	sc := getOrganisationContext(*s)
	sc.KeyPair = kp

	return s.Success("")
}

func addOrganisationToVault(s *stepper.Stepper) stepper.StepResult {
	sc := getOrganisationContext(*s)

	info := &vault.OrganisationInfo{
		Addr:     sc.Args.OrgAddrStr,
		FullName: sc.Args.Name,
		Keys: []vault.KeyPair{
			{
				KeyPair: *sc.KeyPair,
				Active:  true,
			},
		},
		Pow:         sc.Proof,
		Validations: sc.Validations,
	}

	sc.Args.Vault.AddOrganisation(*info)
	err := sc.Args.Vault.Persist()
	if err != nil {
		return s.Failure(fmt.Sprintf("error while saving organisation into vault: %#v", err))
	}

	sc.Organisation = info

	return s.Success("")
}

func uploadOrganisationToResolver(s *stepper.Stepper) stepper.StepResult {
	info := getOrganisationContext(*s).Organisation

	ks := container.Instance.GetResolveService()
	err := ks.UploadOrganisationInfo(*info)
	if err != nil {
		return s.Failure(fmt.Sprintf("error while uploading organisation to the resolver: %s", err.Error()))
	}

	return s.Success("")
}

func checkOrganisationReservedAddress(s *stepper.Stepper) stepper.StepResult {
	orgHash := getOrganisationContext(*s).Args.OrgAddrHash

	ks := container.Instance.GetResolveService()
	domains, _ := ks.CheckReserved(orgHash)

	sc := getOrganisationContext(*s)
	sc.Reserved = len(domains) > 0
	sc.ReservedDomains = domains

	if len(domains) > 0 {
		return s.Notice("Yes. DNS verification is needed in order to register this organisation")
	}

	return s.Success("not reserved")
}

func checkOrganisationReservedDomains(s *stepper.Stepper) stepper.StepResult {

	kp := getOrganisationContext(*s).KeyPair
	if kp == nil {
		info := getOrganisationContext(*s).Organisation
		k := info.GetActiveKey().KeyPair
		kp = &k
	}

	domains := getOrganisationContext(*s).ReservedDomains
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

	msg := internal.GenerateFromFingerprintTemplate(internal.OrganisationProofTemplate, kp.PubKey.Fingerprint(), domains)
	return s.Failure(msg)
}

// getOrganisationContext returns the spinner context structure with all information that is communicated between spinner steps
func getOrganisationContext(s stepper.Stepper) *orgSpinnerContext {
	return s.Ctx.Value(internal.CtxSpinnerContext).(*orgSpinnerContext)
}
