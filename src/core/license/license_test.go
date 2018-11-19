package license

import (
	"testing"
)

func TestNewCommonLicense(t *testing.T) {

	kids := []string{"1234", "345678"}
	objs := []string{"579de65b-67af-4041-9267-3db266102964", "7429c039-c614-489e-af15-1f109cc4f908"}
	cl := NewCommonLicense(kids, objs)

	SetPemFile("/media/sf_win_d/goprojects/opendrm/rsa_private_key.pem")
	cl.Sign()
	t.Logf("common license %s", cl.Serialize(true))
}
