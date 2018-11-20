package license

import (
	"testing"
)

func TestNewCommonLicense(t *testing.T) {
	kids := []string{"123456789", "987345678"}
	objs := []string{"579de65b-67af-4041-9267-3db266102964", "7429c039-c614-489e-af15-1f109cc4f908"}
	cl := NewCommonLicense(kids, objs)

	SetPemFile("/media/sf_win_d/goprojects/opendrm/test/rsa_private_key.pem")
	cl.Sign(false)
	t.Logf("common license: %x", cl.Serialize(false, true))
}

func TestNewChinaDrmLicense(t *testing.T) {
	kids := []string{"12349857423", "34567847562"}
	objs := []string{"579de65b-67af-4041-9267-3db266102964", "7429c039-c614-489e-af15-1f109cc4f908"}
	cl := NewChinaDrmLicense(12345678900, kids, objs)

	SetPemFile("/media/sf_win_d/goprojects/opendrm/test/rsa_private_key.pem")
	cl.Sign(false)
	t.Logf("chinadrm license: %x", cl.Serialize(false, true))
}