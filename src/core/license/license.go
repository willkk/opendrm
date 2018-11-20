package license

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
)

const (
	licenseTypeCommon = iota
	licenseTypeChinaDrm
	licenseTypePlayReady
	licenseTypeWidevine
)

type License interface {
	Serialize() []byte
}

var pemFilePath string

func SetPemFile(pemFile string) error {
	pemFilePath = pemFile
	_, err := os.Stat(pemFile)
	if err != nil {
		log.Fatalf("Stat pem file failed. err=%s", err)
		return err
	}

	return nil
}

func Sign(bytes []byte) ([]byte, error) {
	pkey, err := ioutil.ReadFile(pemFilePath)
	if err != nil {
		return nil, err
	}

	// Read private key from pem file
	block, _ := pem.Decode(pkey)
	if block == nil { // 失败情况
		log.Fatalf("Decode pem failed.")
		return nil, errors.New("no pem block found")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Parse private key failed. Err=%s", err)
		return nil, err
	}

	h := sha1.New()
	h.Write(bytes)
	digest := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA1, digest)
	if err != nil {
		log.Fatalf("Sign failed. Err=%s", err)
		return nil, err
	}

	return sig, nil
}
