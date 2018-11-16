package main

import (
	"core/key"
	"core/license"
	"core/server"
	"encoding/json"
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
	Deviceid string
	// required
	Kids []string `json:"kids"`
	// optional
	ClientId *string
	// optional
	ContentId *string `json:"content_id"`
}

type LicenseResp struct {
	DeviceId string
	Licenses []*license.License
}

func AcquireLicense(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	//
	kids := r.Form["kids"]
	log.Printf("kids:%v")

}

func main() {
	keyServer := server.NewKeyServer(":8090")
	http.HandleFunc("/genkey", GenKey)
	http.HandleFunc("/acquirelicense", AcquireLicense)
	keyServer.Start()
}
