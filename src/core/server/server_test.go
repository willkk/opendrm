package server

import (
	"core/key"
	"encoding/json"
	"net/http"
	"testing"
)

func GenKey(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	//kid := r.Form["kid"]

	kengen := key.NewKeyGenerator(nil)
	key, kid := kengen.GenRandKey()
	resp := struct {
		Key []byte
		KId string
	}{
		Key: key,
		KId: kid,
	}
	data, _ := json.Marshal(&resp)
	w.Write(data)
}

func TestKeyServer_Start(t *testing.T) {
	keyServer := NewKeyServer(":8090")
	http.HandleFunc("/genkey", GenKey)
	keyServer.Start()
}
