package license

import "testing"

func TestNewCommonLicense(t *testing.T) {
	kids := []string{"1234", "345678"}
	cl := NewCommonLicense(kids)

	t.Logf("common license %v", cl.Serialize())
}
