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
	"crypto/sha1"
	"testing"
)

var comnLicenseSig []byte
var hashed []byte
func TestNewCommonLicense(t *testing.T) {
	kids := []string{"123456789", "987345678"}
	objs := []string{"579de65b-67af-4041-9267-3db266102964", "7429c039-c614-489e-af15-1f109cc4f908"}
	certId := "b8c35868-4b94-4ad9-a0bc-c85e9a03b1de"
	cl := NewCommonLicense(kids, objs, certId)

	sum := sha1.Sum(cl.Serialize(false, false))
	hashed = sum[:]

	SetPemFile("/media/sf_win_d/goprojects/opendrm/test/rsa_private_key.pem")
	comnLicenseSig, _ = cl.Sign(false)
	//t.Logf("common license: %s", cl.Base64String())
}

func TestNewChinaDrmLicense(t *testing.T) {
	kids := []string{"12349857423", "34567847562"}
	objs := []string{"579de65b-67af-4041-9267-3db266102964", "7429c039-c614-489e-af15-1f109cc4f908"}
	certId := "b8c35868-4b94-4ad9-a0bc-c85e9a03b1de"
	cdl := NewChinaDrmLicense(12345678900, kids, objs, certId)

	SetPemFile("/media/sf_win_d/goprojects/opendrm/test/rsa_private_key.pem")
	cdl.Sign(false)
	//t.Logf("chinadrm license: %s", cdl.Base64String())
}

func TestVerify(t *testing.T) {
	SetPemFile("/media/sf_win_d/goprojects/opendrm/test/rsa_public_key.pem")
	err := Verify(hashed, comnLicenseSig)
	if err != nil {
		t.Fatalf("Verify failed.")
	} else {
		t.Logf("Verify ok.")
	}
}
