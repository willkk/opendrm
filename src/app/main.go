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
	DeviceId string
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
	log.Printf("kids:%v", req.Kids)

	// Query or calculate the key of related key id
	keyGen := key.NewKeyGenerator(nil)
	keymap := make(map[string][]byte, 0)
	for _, kid := range req.Kids {
		key := keyGen.GenKeyByDefaultSeed(kid)
		keymap[kid] = key
	}

	// Generate license

}

func main() {
	keyServer := server.NewKeyServer(":8090")
	http.HandleFunc("/genkey", GenKey)
	http.HandleFunc("/acquirelicense", AcquireLicense)
	keyServer.Start()
}
