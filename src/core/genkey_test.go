package core

import "testing"

/*
func TestGenerateKeyAndKid(t *testing.T) {
	key, kid := GenerateRandKeyAndKid()
	t.Logf("key:%x, kid:%s", key, kid)
}
*/
func TestGenerateKeyAndKidBySeed(t *testing.T) {
	kid := "3bff1f0c-0b16-4641-84af-8832f1cd37b5"
	ck := GenerateKeyAndKidBySeed(kid)
	t.Logf("key:%x", ck)
}
