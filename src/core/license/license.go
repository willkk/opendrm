package license

import (
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
