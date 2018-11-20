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
