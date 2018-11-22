/*
	Opendrm, an open source implementation of industry-grade DRM
	(Digital Rights Management) or Key System.
	Copyright (C) 2018  wilkk

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
	Base64String() string
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

// Generate private key by command 'openssl genrsa -out rsa_private_key.pem 1024'
// Generate public key by command 'openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem'
func Sign(bytes []byte) ([]byte, error) {
	pkey, err := ioutil.ReadFile(pemFilePath)
	if err != nil {
		return nil, err
	}

	// Read private key from pem file
	block, _ := pem.Decode(pkey)
	if block == nil {
		log.Fatalf("Decode pem failed.")
		return nil, errors.New("no pem block found")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Parse private key failed. Err=%s", err)
		return nil, err
	}

	// Calculate hash of original data
	digest := sha1.Sum(bytes)

	sig, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA1, digest[:])
	if err != nil {
		log.Fatalf("Sign failed. Err=%s", err)
		return nil, err
	}

	return sig, nil
}

func Verify(hashed []byte, signature []byte) error {
	pkey, err := ioutil.ReadFile(pemFilePath)
	if err != nil {
		log.Fatalf("ReadFile failed. Err=%x", err)
		return err
	}

	// Decode public key from pem file
	block, _ := pem.Decode(pkey)
	if block == nil {
		log.Fatalf("Decode pem failed.")
		return errors.New("No pem block found.")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Parse public key failed. Err=%s", err)
		return err
	}

	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA1, hashed, signature)
	if err != nil {
		log.Fatalf("Verify signature failed. Err=%s", err)
		return err
	}

	return nil
}
