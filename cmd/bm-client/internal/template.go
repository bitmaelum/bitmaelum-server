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

package internal

import (
	"bytes"
	"fmt"
	"text/template"
)

// AccountCreatedTemplate is the template displayed when an account has been created
const AccountCreatedTemplate = `
*****************************************************************************
!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORT
*****************************************************************************

We have generated a private key which allows you to control your account. 
If, for any reason, you lose this key, you will need to use the following 
words in order to recreate the key:

{{ .Mnemonic }}

Write these words down and store them in a secure environment. They are the 
ONLY way to recover your private key in case you lose it.

WITHOUT THESE WORDS, ALL ACCESS TO YOUR ACCOUNT IS LOST!
`

// OrganisationCreatedTemplate is the template displayed when an organisation has been created
const OrganisationCreatedTemplate = `
*****************************************************************************
!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORTANT!IMPORT
*****************************************************************************

We have generated a private key which allows you to control your organisation. 
If, for any reason, you lose this key, you will need to use the following 
words in order to recreate the key:

{{ .Mnemonic }}

Write these words down and store them in a secure environment. They are the 
ONLY way to recover your private key in case you lose it.

WITHOUT THESE WORDS, ALL ACCESS TO YOUR ACCOUNT IS LOST!
`

// AccountProofTemplate is the template displayed when a reserved address is trying to be created
const AccountProofTemplate = `could not find proof in the DNS.

In order to register this reserved address, make sure you add the following information to the DNS:

   _bitmaelum TXT {{ .Fingerprint }}

This entry could be added to any of the following domains: {{ .Domains }}. Once we have found the entry, we can 
register the account onto the keyserver. For more information, please visit https://bitmaelum.com/reserved
`

// OrganisationProofTemplate is the template displayed when a reserved organisation is trying to be created
const OrganisationProofTemplate = `could not find proof in the DNS.

In order to register this reserved organisation, make sure you add the following information to the DNS:

    _bitmaelum TXT {{ .Fingerprint }}

This entry could be added to any of the following domains: {{ .Domains }}. Once we have found the entry, we can 
register the organisation onto the keyserver. For more information, please visit https://bitmaelum.com/reserved
`

// Generate from generic template data
func generateFromTemplateData(messageTemplate string, data interface{}) string {
	msg := fmt.Sprintf("%v", data) // when things fail
	tmpl, err := template.New("template").Parse(messageTemplate)
	if err != nil {
		fmt.Println(err)
		return msg
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		fmt.Println(err)
		return msg
	}

	return buf.String()
}

// GenerateFromFingerprintTemplate generates fingerprint template
func GenerateFromFingerprintTemplate(messageTemplate string, fingerprint string, domains []string) string {
	type tplData struct {
		Fingerprint string
		Domains     []string
	}

	return generateFromTemplateData(messageTemplate, tplData{
		Fingerprint: fingerprint,
		Domains:     domains,
	})
}

// GenerateFromMnemonicTemplate generates mnemonic template
func GenerateFromMnemonicTemplate(messageTemplate string, mnemonic string) string {
	type tplData struct {
		Mnemonic string
	}

	return generateFromTemplateData(messageTemplate, tplData{
		Mnemonic: mnemonic,
	})
}
