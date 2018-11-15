package core

import (
	"crypto/sha256"
	"log"
	"math/rand"
	"os/exec"
	"time"
)

// At least 30 bytes
var seed  = []byte("b1cc1aa664122baca692107d4ba5d6d21ef9787ee82f8020ec93adcc25d44b8f")

// Based on https://docs.microsoft.com/en-us/playready/specifications/playready-key-seed
// Ck(KID) = f(KID, KeySeed)
func GenerateKeyAndKidBySeed(uuid string) []byte {
	drm_aes_keysize_128 := 16
	contentKey := make([]byte, drm_aes_keysize_128)

	// Truncate seed to 30 bytes
	truncKeySeed := seed[:30]
	// Get the keyId bytes.
	keyIdBytes := []byte(uuid)

	// Calculate the SHA of truncKeySeed and keyIdBytes.
	shaA := sha256.New()
	shaA.Write(truncKeySeed)
	shaA.Write(keyIdBytes)
	outputA := shaA.Sum(nil)

	// Calculate the SHA of truncKeySeed, keyIdBytes, and truncKeySeed.
	shaB := sha256.New()
	shaB.Write(truncKeySeed)
	shaB.Write(keyIdBytes)
	shaB.Write(truncKeySeed)
	outputB := shaB.Sum(nil)

	// Calculate the SHA of truncKeySeed, keyIdBytes, truncKeySeed again, and keyIdBytes again.
	shaC := sha256.New()
	shaC.Write(truncKeySeed)
	shaC.Write(keyIdBytes)
	shaC.Write(truncKeySeed)
	shaC.Write(keyIdBytes)
	outputC := shaB.Sum(nil)

	for i := 0; i< drm_aes_keysize_128; i++ {
		contentKey[i] = outputA[i] ^ outputA[i + drm_aes_keysize_128] ^
			outputB[i] ^ outputB[i + drm_aes_keysize_128] ^
			outputC[i] ^ outputC[i + drm_aes_keysize_128]
	}

	return contentKey
}

func GenerateRandKeyAndKid() ([]byte, string) {
	rnd := rand.New(rand.NewSource(time.Now().Unix()))
	key := make([]byte, 16)
	rnd.Read(key)

	kid, err := exec.Command("uuidgen").Output()
	if err != nil {
		log.Fatal(err)
	}

	return key, string(kid)
}