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
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"

	"github.com/jorrizza/ed2curve25519"
	"github.com/vtolstov/jwt-go"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var errCannotFetchScalar = errors.New("error while getting a random scalar")

// KeyEd25519 is the ed25519 keytype
type KeyEd25519 struct {
}

// NewEd25519Key will return the keytype of ed25519. There is only a single curve here.
func NewEd25519Key() KeyType {
	return &KeyEd25519{}
}

// CanEncrypt returns true if the key(type) is able to be used for encryption/decryption
func (k *KeyEd25519) CanEncrypt() bool {
	return false
}

// CanKeyExchange returns true if the key(type) is able to be used for key exchange
func (k *KeyEd25519) CanKeyExchange() bool {
	return true
}

// CanDualKeyExchange returns true if the key(type) is able to be used for a dual key exchange
func (k *KeyEd25519) CanDualKeyExchange() bool {
	return true
}

// String returns a string representation of the key type ("rsa", "ecdsa", "ed25519" etc)
func (k *KeyEd25519) String() string {
	return "ed25519"
}

// ParsePrivateKeyData will parse a string representation of a key and returns the given key
func (k *KeyEd25519) ParsePrivateKeyData(buf []byte) (interface{}, error) {
	return x509.ParsePKCS8PrivateKey(buf)
}

// ParsePrivateKeyInterface will parse a interface and returns the key representation
func (k *KeyEd25519) ParsePrivateKeyInterface(key interface{}) ([]byte, error) {
	switch key := key.(type) {
	case ed25519.PrivateKey:
		return x509.MarshalPKCS8PrivateKey(key)
	}

	return nil, errIncorrectKey
}

// GenerateKeyPair will generate a new keypair for this keytype. io.Reader can be deterministic if needed
func (k *KeyEd25519) GenerateKeyPair(r io.Reader) (*PrivKey, *PubKey, error) {
	b := make([]byte, 32)

	// Reader could hold either 24 bytes (192bit seed) or new style 32 bytes (256 bit seed)
	n, err := io.ReadFull(r, b)

	// Something other than EOF happened
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, nil, err
	}

	// Not the correct number of bytes read
	if n != 24 && n != 32 {
		return nil, nil, err
	}

	// Stretch to 256 bits if smaller.. or just hkdf anyways
	rd := hkdf.New(sha256.New, b[:n], []byte{}, []byte{})
	expBuf := make([]byte, 32)
	_, err = io.ReadFull(rd, expBuf)
	if err != nil {
		return nil, nil, err
	}

	// Generate keypair
	pk := ed25519.NewKeyFromSeed(expBuf[:32])
	privKey, err := PrivateKeyFromInterface(k, pk)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := PublicKeyFromInterface(k, pk.Public())
	if err != nil {
		return nil, nil, err
	}

	return privKey, pubKey, nil
}

// JWTSignMethod will return the signing method used for this keytype
func (k *KeyEd25519) JWTSignMethod() jwt.SigningMethod {
	return &SigningMethodEdDSA{}
}

// JWTHasValidSignMethod will return true when this keytype has been used for signing the token
func (k *KeyEd25519) JWTHasValidSignMethod(token *jwt.Token) bool {
	_, ok := token.Method.(*SigningMethodEdDSA)
	return ok
}

// Verify will verify the signature with the public key
func (k *KeyEd25519) Verify(key PubKey, message []byte, sig []byte) (bool, error) {
	return ed25519.Verify(key.K.(ed25519.PublicKey), message, sig), nil
}

// Sign will sign the given bytes with the private key
func (k *KeyEd25519) Sign(reader io.Reader, key PrivKey, message []byte) ([]byte, error) {
	return ed25519.Sign(key.K.(ed25519.PrivateKey), message), nil
}

// Encrypt will encrypt the given message with the public key.
func (k *KeyEd25519) Encrypt(key PubKey, msg []byte) ([]byte, *EncryptionSettings, error) {
	secret, txID, err := DualKeyExchange(key)
	if err != nil {
		return nil, nil, err
	}

	encryptedMessage, err := MessageEncrypt(secret, msg)
	if err != nil {
		return nil, nil, err
	}

	return encryptedMessage, &EncryptionSettings{
		Type:          Ed25519AES,
		TransactionID: txID.ToHex(),
	}, nil
}

// Decrypt will decrypt the given bytes with the private key
func (k *KeyEd25519) Decrypt(key PrivKey, settings *EncryptionSettings, cipherText []byte) ([]byte, error) {
	if settings.Type != Ed25519AES {
		return nil, errors.New("cannot decrypt this encryption type")
	}

	tx, err := TxIDFromString(settings.TransactionID)
	if err != nil {
		return nil, err
	}

	secret, ok, err := DualKeyGetSecret(key, *tx)
	if !ok || err != nil {
		return nil, err
	}

	return MessageDecrypt(secret, cipherText)
}

// ParsePublicKeyData will parse a interface and returns the key representation
func (k *KeyEd25519) ParsePublicKeyData(buf []byte) (interface{}, error) {
	return x509.ParsePKIXPublicKey(buf)
}

// ParsePublicKeyInterface will parse a interface and returns the key representation
func (k *KeyEd25519) ParsePublicKeyInterface(key interface{}) ([]byte, error) {
	switch key := key.(type) {
	case ed25519.PublicKey:
		return x509.MarshalPKIXPublicKey(key)
	}

	return nil, errIncorrectKey
}

// KeyExchange allows for a key exchange (if possible in the keytype)
func (k *KeyEd25519) KeyExchange(privK PrivKey, pubK PubKey) ([]byte, error) {
	x25519priv := ed2curve25519.Ed25519PrivateKeyToCurve25519(privK.K.(ed25519.PrivateKey))
	x25519pub := ed2curve25519.Ed25519PublicKeyToCurve25519(pubK.K.(ed25519.PublicKey))

	return curve25519.X25519(x25519priv, x25519pub)
}

// DualKeyExchange allows for a ECIES key exchange
func (k *KeyEd25519) DualKeyExchange(pub PubKey) ([]byte, *TransactionID, error) {
	rs, err := generateRandomScalar()
	if err != nil {
		return nil, nil, errCannotFetchScalar
	}

	r := ed25519.NewKeyFromSeed(rs)
	R := r.Public()

	// Step 1: D = rA
	D, err := curve25519.X25519(
		ed2curve25519.Ed25519PrivateKeyToCurve25519(r.Seed()),
		ed2curve25519.Ed25519PublicKeyToCurve25519(pub.K.(ed25519.PublicKey)),
	)
	if err != nil {
		return nil, nil, err
	}

	f := hs(D)      // Step 2: f = Hs(D)
	P := f.Public() // Step 3-5: convert F into private Key (F=fG)

	return D, &TransactionID{
		P: P.(ed25519.PublicKey)[:32],
		R: R.(ed25519.PublicKey)[:32],
	}, nil
}
