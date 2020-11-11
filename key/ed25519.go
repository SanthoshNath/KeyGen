package key

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"keygen/io"
)

type ED25519Key struct {
	privateKey ed25519.PrivateKey
	publicKey ed25519.PublicKey
}

func NewED25519Key() *ED25519Key {
	return &ED25519Key{ ed25519.PrivateKey{}, ed25519.PublicKey{}}
}

func (ed25519Key *ED25519Key) Generate() error {
	var err error

	ed25519Key.publicKey, ed25519Key.privateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	return nil
}

func (ed25519Key *ED25519Key) Export(filepath string) error {
	privateKeyByte, err := x509.MarshalPKCS8PrivateKey(ed25519Key.privateKey)
	if err != nil {
		return err
	}

	publicKeyByte, err := x509.MarshalPKIXPublicKey(ed25519Key.publicKey)
	if err != nil {
		return err
	}

	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "ED PRIVATE KEY",
			Bytes: privateKeyByte,
		},
	)

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyByte,
		},
	)

	err = io.Write(filepath+"/id_ed25519", string(privateKeyPem))
	if err != nil {
		return err
	}

	err = io.Write(filepath+"/id_ed25519.pub", string(publicKeyPem))
	if err != nil {
		return err
	}

	return nil
}
