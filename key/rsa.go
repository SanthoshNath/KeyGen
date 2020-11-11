package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"keygen/io"
)

type RSAKey struct {
	bits       int
	privateKey *rsa.PrivateKey
}

func NewRSAKey(bits int) *RSAKey {
	return &RSAKey{bits, &rsa.PrivateKey{}}
}

func (rsaKey *RSAKey) Generate() error {
	var err error

	rsaKey.privateKey, err = rsa.GenerateKey(rand.Reader, rsaKey.bits)
	if err != nil {
		return err
	}

	return nil
}

func (rsaKey *RSAKey) Export(filepath string) error {
	privateKeyByte := x509.MarshalPKCS1PrivateKey(rsaKey.privateKey)

	publicKeyByte, err := x509.MarshalPKIXPublicKey(&rsaKey.privateKey.PublicKey)
	if err != nil {
		return err
	}

	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyByte,
		},
	)

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyByte,
		},
	)

	err = io.Write(filepath+"/id_rsa", string(privateKeyPem))
	if err != nil {
		return err
	}

	err = io.Write(filepath+"/id_rsa.pub", string(publicKeyPem))
	if err != nil {
		return err
	}

	return nil
}
