package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	fluffycore_utils "github.com/fluffy-bunny/fluffycore/utils"
)

// EncryptPemBlock encrypts a PEM block using RFC 1423 encryption.
// WARNING: RFC 1423 encryption is deprecated and insecure. It's vulnerable to padding oracle attacks.
// Both x509.EncryptPEMBlock and x509.DecryptPEMBlock are deprecated due to security vulnerabilities.
// For new applications, consider:
// 1. Using unencrypted PKCS#8 keys with secure key management systems
// 2. Implementing application-level encryption with modern algorithms
// 3. Using hardware security modules (HSMs) or cloud key vaults
func EncryptPemBlock(block *pem.Block, password string, alg x509.PEMCipher) error {
	if fluffycore_utils.IsNotEmptyOrNil(password) {
		if x509.PEMCipher(0) == alg {
			alg = x509.PEMCipherAES256
		}
		// Using deprecated x509.EncryptPEMBlock for backward compatibility
		// WARNING: This function is deprecated and insecure - use at your own risk
		newBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), alg)
		if nil != err {
			return err
		}
		if nil == block.Headers {
			block.Headers = newBlock.Headers
		} else {
			for hdr, val := range newBlock.Headers {
				block.Headers[hdr] = val
			}
		}
		block.Bytes = newBlock.Bytes
	}
	return nil
}

// DecryptPemBlock decrypts a PEM block encrypted with RFC 1423 encryption.
// WARNING: RFC 1423 encryption is deprecated and insecure. It's vulnerable to padding oracle attacks.
// Both x509.EncryptPEMBlock and x509.DecryptPEMBlock are deprecated due to security vulnerabilities.
// Consider migrating to secure key management solutions for better security.
func DecryptPemBlock(block *pem.Block, password string) (err error) {
	// Check if PEM block is encrypted by looking for RFC 1423 headers
	// This replaces the deprecated x509.IsEncryptedPEMBlock
	if block.Headers != nil && block.Headers["Proc-Type"] != "" && block.Headers["DEK-Info"] != "" {
		// Using deprecated x509.DecryptPEMBlock for backward compatibility
		// WARNING: This function is deprecated and insecure - use at your own risk
		data, err := x509.DecryptPEMBlock(block, []byte(password))
		if nil != err {
			return err
		} else {
			delete(block.Headers, "Proc-Type")
			delete(block.Headers, "DEK-Info")
			block.Bytes = data
		}
	}
	return nil
}

func decodePrivatePem(password string, pemEncoded string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	var block *pem.Block
	block, _ = pem.Decode([]byte(pemEncoded))
	var err error
	if password != "" {
		err = DecryptPemBlock(block, password)
		if nil != err {
			return nil, nil, err
		}
	}

	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

func decode(password string, pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	var block *pem.Block
	block, _ = pem.Decode([]byte(pemEncoded))
	var err error
	if password != "" {
		err = DecryptPemBlock(block, password)
		if nil != err {
			return nil, nil, err
		}
	}

	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey, nil
}
func encode(password string, privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	// Convert it to pem
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	}
	var pemEncoded []byte
	// Encrypt the pem
	if password != "" {
		// WARNING: Using deprecated RFC 1423 encryption
		// For production use, consider generating unencrypted keys and storing them securely
		err = EncryptPemBlock(block, password, x509.PEMCipherAES256)

		if err != nil {
			return "", "", err
		}
		//	DecryptedPEMBlock, _ := x509.DecryptPEMBlock(block, []byte(password))
		//	fmt.Println(string(DecryptedPEMBlock))
	}
	pemEncoded = pem.EncodeToMemory(block)

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "EC  PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub), nil
}

func pubBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
}

func GenerateECDSAPublicPrivateKeySet(password string) (privateKey *ecdsa.PrivateKey, privateEncoded string, publicEncoded string, err error) {
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", err
	}

	privateEncoded, publicEncoded, err = encode(password, privateKey, &privateKey.PublicKey)
	return
}
