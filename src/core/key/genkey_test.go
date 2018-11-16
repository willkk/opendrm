package key

import "testing"

func TestGenerateKeyAndKid(t *testing.T) {
	keyGen := NewKeyGenerator(nil)
	key, kid := keyGen.GenRandKey()
	t.Logf("key:%x, kid:%s", key, kid)
}

func TestGenerateKeyAndKidBySeed(t *testing.T) {
	kid := "3bff1f0c-0b16-4641-84af-8832f1cd37b5"
	keyGen := NewKeyGenerator(defaultKeySeed)
	ck := keyGen.GenKeyBySeed(kid)
	t.Logf("key:%x", ck)
}
