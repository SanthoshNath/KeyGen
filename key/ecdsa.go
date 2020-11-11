package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"keygen/io"
)

type ECDSAKey struct {
	curve      elliptic.Curve
	privateKey *ecdsa.PrivateKey
}

func NewECDSAKey(curve elliptic.Curve) *ECDSAKey {
	return &ECDSAKey{curve, &ecdsa.PrivateKey{}}
}

func (ecdsaKey *ECDSAKey) Generate() error {
	var err error

	ecdsaKey.privateKey, err = ecdsa.GenerateKey(ecdsaKey.curve, rand.Reader)
	if err != nil {
		return err
	}

	return nil
}

func (ecdsaKey *ECDSAKey) Export(filepath string) error {
	privateKeyByte, err := x509.MarshalECPrivateKey(ecdsaKey.privateKey)
	if err != nil {
		return err
	}

	publicKeyByte, err := x509.MarshalPKIXPublicKey(&ecdsaKey.privateKey.PublicKey)
	if err != nil {
		return err
	}

	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyByte,
		},
	)

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyByte,
		},
	)

	err = io.Write(filepath+"/id_ecdsa", string(privateKeyPem))
	if err != nil {
		return err
	}

	err = io.Write(filepath+"/id_ecdsa.pub", string(publicKeyPem))
	if err != nil {
		return err
	}

	return nil
}
