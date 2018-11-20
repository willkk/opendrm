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

package main

import (
	"core/key"
	"core/license"
	"core/server"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type KeyResp struct {
	Key []byte `json:"key"`
	Kid string `json:"kid"`
}

func GenKey(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	//kid := r.Form["kid"]

	kengen := key.NewKeyGenerator(nil)
	key, kid := kengen.GenRandKey()
	resp := KeyResp{
		Key: key,
		Kid: kid,
	}
	data, _ := json.Marshal(&resp)
	w.Write(data)
}

type LicenseRequest struct {
	// required
	DeviceId string `json:"device_id"`
	// required
	Kids []string `json:"kids"`
	// optional
	ClientId *string
	// optional
	ContentId *string `json:"content_id"`
}

type LicenseResp struct {
	DeviceId string
	Licenses []string
}

func AcquireLicense(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	reqData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Read request failed. err=%s", err)
		return
	}
	log.Printf("data:%s", string(reqData))

	req := &LicenseRequest{}
	err = json.Unmarshal(reqData, req)
	if err != nil {
		log.Printf("Unmarshal request failed. err=%s", err)
		return
	}
	log.Printf("kids:%v", req)

	// Query objects to be authorized
	objs := []string{"07fba7c4-a5d3-43b2-973b-0b474a0b9ede"}
	certId := "47946232-dad5-4b46-b1e6-4f0b581108dc"
	// Generate license
	lic := license.NewCommonLicense(req.Kids, objs, certId)
	licenseStr := lic.Base64String()

	resp := &LicenseResp{
		DeviceId: req.DeviceId,
		Licenses: []string{licenseStr},
	}

	respData, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Marshal response failed. Err=%s", err)
		return
	}
	w.Write(respData)

}

func main() {
	keyServer := server.NewKeyServer(":8090")
	http.HandleFunc("/genkey", GenKey)
	http.HandleFunc("/acquirelicense", AcquireLicense)
	keyServer.Start()
}
