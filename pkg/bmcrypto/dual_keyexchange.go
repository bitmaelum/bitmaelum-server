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

package bmcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"

	"github.com/jorrizza/ed2curve25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

var (
	errIncorrectTxID               = errors.New("incorrect txID len (must be 64byte)")
	errCannotuseForDualKeyExchange = errors.New("this type cannot be used for dual key exchange")
)

// The dual key exchange system is taken from https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-part-2-stealth-addresses

// TransactionID is a structure that holds the P and R value that is needed to verify the dual key signature
type TransactionID struct {
	P []byte
	R []byte
}

// ToHex converts a transaction ID to a hexadecimal representation
func (txID TransactionID) ToHex() string {
	return hex.EncodeToString(bytes.Join([][]byte{txID.P, txID.R}, []byte{}))
}

// TxIDFromString converts a hexadecimal presentation into a TransactionID
func TxIDFromString(s string) (*TransactionID, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if len(b) != 64 {
		return nil, errIncorrectTxID
	}

	return &TransactionID{
		P: b[:32],
		R: b[32:],
	}, nil
}

// DualKeyExchange is a Dual DH key exchange that uses an intermediate key. This key is randomized and provide a way
// for alice and bob to communicate through a non-deterministic DH.
// It returns the (shared) secret, a transaction ID that needs to be send over to the other user.
func DualKeyExchange(pub PubKey) ([]byte, *TransactionID, error) {
	if !pub.Type.CanDualKeyExchange() {
		return nil, nil, errCannotuseForDualKeyExchange
	}

	return pub.Type.DualKeyExchange(pub)
}

// DualKeyGetSecret verifies if the transaction ID matches our private key. If so, it will return the
// secret that has been exchanged
func DualKeyGetSecret(priv PrivKey, txID TransactionID) ([]byte, bool, error) {
	if !priv.Type.CanDualKeyExchange() {
		return nil, false, errCannotuseForDualKeyExchange
	}

	// Step 1-3: D' = aR
	Dprime, err := curve25519.X25519(
		ed2curve25519.Ed25519PrivateKeyToCurve25519(priv.K.(ed25519.PrivateKey).Seed()),
		ed2curve25519.Ed25519PublicKeyToCurve25519(txID.R),
	)
	if err != nil {
		return nil, false, err
	}

	fprime := hs(Dprime)      // Step 4: f' = Hs(D')
	Pprime := fprime.Public() // Step 5-6: P = F' = f'G

	// If Pprime = P, then we know both alice and bob uses D (and Dprime) as the secret
	if subtle.ConstantTimeCompare(txID.P, Pprime.(ed25519.PublicKey)) == 1 {
		return Dprime, true, nil
	}

	return nil, false, nil
}

func generateRandomScalar() ([]byte, error) {
	// get 256bits/32bytes of random data
	buf := make([]byte, 32)
	_, err := io.ReadFull(randReader, buf)
	if err != nil {
		return nil, err
	}

	var buf32 [32]byte
	copy(buf32[:], buf[:32])

	scReduce32(&buf32)
	return buf32[:], nil
}

func hs(b []byte) ed25519.PrivateKey {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)

	var buf32 [32]byte
	copy(buf32[:], h.Sum(nil))

	scReduce32(&buf32)
	return ed25519.NewKeyFromSeed(buf32[:])
}

func load3(in []byte) int64 {
	var r int64
	r = int64(in[0])
	r |= int64(in[1]) << 8
	r |= int64(in[2]) << 16
	return r
}

func load4(in []byte) int64 {
	var r int64
	r = int64(in[0])
	r |= int64(in[1]) << 8
	r |= int64(in[2]) << 16
	r |= int64(in[3]) << 24
	return r
}

func scReduce32(s *[32]byte) {
	s0 := 2097151 & load3(s[:])
	s1 := 2097151 & (load4(s[2:]) >> 5)
	s2 := 2097151 & (load3(s[5:]) >> 2)
	s3 := 2097151 & (load4(s[7:]) >> 7)
	s4 := 2097151 & (load4(s[10:]) >> 4)
	s5 := 2097151 & (load3(s[13:]) >> 1)
	s6 := 2097151 & (load4(s[15:]) >> 6)
	s7 := 2097151 & (load3(s[18:]) >> 3)
	s8 := 2097151 & load3(s[21:])
	s9 := 2097151 & (load4(s[23:]) >> 5)
	s10 := 2097151 & (load3(s[26:]) >> 2)
	s11 := (load4(s[28:]) >> 7)
	s12 := int64(0)
	var carry [12]int64
	carry[0] = (s0 + (1 << 20)) >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[2] = (s2 + (1 << 20)) >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[4] = (s4 + (1 << 20)) >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[6] = (s6 + (1 << 20)) >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[8] = (s8 + (1 << 20)) >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[10] = (s10 + (1 << 20)) >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21
	carry[1] = (s1 + (1 << 20)) >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[3] = (s3 + (1 << 20)) >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[5] = (s5 + (1 << 20)) >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[7] = (s7 + (1 << 20)) >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[9] = (s9 + (1 << 20)) >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[11] = (s11 + (1 << 20)) >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	// Duplicated code, so placed in a func
	carryFunc := func() {
		carry[0] = s0 >> 21
		s1 += carry[0]
		s0 -= carry[0] << 21
		carry[1] = s1 >> 21
		s2 += carry[1]
		s1 -= carry[1] << 21
		carry[2] = s2 >> 21
		s3 += carry[2]
		s2 -= carry[2] << 21
		carry[3] = s3 >> 21
		s4 += carry[3]
		s3 -= carry[3] << 21
		carry[4] = s4 >> 21
		s5 += carry[4]
		s4 -= carry[4] << 21
		carry[5] = s5 >> 21
		s6 += carry[5]
		s5 -= carry[5] << 21
		carry[6] = s6 >> 21
		s7 += carry[6]
		s6 -= carry[6] << 21
		carry[7] = s7 >> 21
		s8 += carry[7]
		s7 -= carry[7] << 21
		carry[8] = s8 >> 21
		s9 += carry[8]
		s8 -= carry[8] << 21
		carry[9] = s9 >> 21
		s10 += carry[9]
		s9 -= carry[9] << 21
		carry[10] = s10 >> 21
		s11 += carry[10]
		s10 -= carry[10] << 21
	}
	carryFunc()
	carry[11] = s11 >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901

	carryFunc()

	s[0] = byte(s0 >> 0)
	s[1] = byte(s0 >> 8)
	s[2] = byte((s0 >> 16) | (s1 << 5))
	s[3] = byte(s1 >> 3)
	s[4] = byte(s1 >> 11)
	s[5] = byte((s1 >> 19) | (s2 << 2))
	s[6] = byte(s2 >> 6)
	s[7] = byte((s2 >> 14) | (s3 << 7))
	s[8] = byte(s3 >> 1)
	s[9] = byte(s3 >> 9)
	s[10] = byte((s3 >> 17) | (s4 << 4))
	s[11] = byte(s4 >> 4)
	s[12] = byte(s4 >> 12)
	s[13] = byte((s4 >> 20) | (s5 << 1))
	s[14] = byte(s5 >> 7)
	s[15] = byte((s5 >> 15) | (s6 << 6))
	s[16] = byte(s6 >> 2)
	s[17] = byte(s6 >> 10)
	s[18] = byte((s6 >> 18) | (s7 << 3))
	s[19] = byte(s7 >> 5)
	s[20] = byte(s7 >> 13)
	s[21] = byte(s8 >> 0)
	s[22] = byte(s8 >> 8)
	s[23] = byte((s8 >> 16) | (s9 << 5))
	s[24] = byte(s9 >> 3)
	s[25] = byte(s9 >> 11)
	s[26] = byte((s9 >> 19) | (s10 << 2))
	s[27] = byte(s10 >> 6)
	s[28] = byte((s10 >> 14) | (s11 << 7))
	s[29] = byte(s11 >> 1)
	s[30] = byte(s11 >> 9)
	s[31] = byte(s11 >> 17)
}
