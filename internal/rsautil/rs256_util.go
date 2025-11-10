package rsautil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func EncryptPemBlock(block *pem.Block, password string, alg x509.PEMCipher) error {
	if len(password) == 0 {
		return nil
	}
	if alg == x509.PEMCipher(0) {
		alg = x509.PEMCipherAES256
	}
	newBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), alg)
	if err != nil {
		return err
	}
	if block.Headers == nil {
		block.Headers = newBlock.Headers
	} else {
		for hdr, val := range newBlock.Headers {
			block.Headers[hdr] = val
		}
	}
	block.Bytes = newBlock.Bytes
	return nil
}

func DecryptPemBlock(block *pem.Block, password string) error {
	if !x509.IsEncryptedPEMBlock(block) {
		return nil
	}
	data, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return err
	}
	delete(block.Headers, "Proc-Type")
	delete(block.Headers, "DEK-Info")
	block.Bytes = data
	return nil
}

func decodePrivatePem(password string, pemEncoded string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, nil, errors.New("failed to decode private key pem block")
	}
	if password != "" {
		if err := DecryptPemBlock(block, password); err != nil {
			return nil, nil, err
		}
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func decode(password string, pemEncoded string, pemEncodedPub string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, nil, errors.New("failed to decode private key pem block")
	}
	if password != "" {
		if err := DecryptPemBlock(block, password); err != nil {
			return nil, nil, err
		}
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	if blockPub == nil {
		return nil, nil, errors.New("failed to decode public key pem block")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(blockPub.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func encode(password string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) (string, string, error) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if password != "" {
		if err := EncryptPemBlock(block, password, x509.PEMCipherAES256); err != nil {
			return "", "", err
		}
	}
	privatePEM := pem.EncodeToMemory(block)

	pubBytes := x509.MarshalPKCS1PublicKey(publicKey)
	pubBlock := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes}
	publicPEM := pem.EncodeToMemory(pubBlock)

	return string(privatePEM), string(publicPEM), nil
}

func GenerateRSAPublicPrivateKeySet(password string) (*rsa.PrivateKey, string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", "", err
	}
	privateEncoded, publicEncoded, err := encode(password, privateKey, &privateKey.PublicKey)
	if err != nil {
		return nil, "", "", err
	}
	return privateKey, privateEncoded, publicEncoded, nil
}
