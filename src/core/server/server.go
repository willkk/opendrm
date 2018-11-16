package server

import "net/http"

type KeyServer struct {
	server *http.Server
}

func NewKeyServer(addr string) *KeyServer {
	return &KeyServer{
		server: &http.Server{
			Addr: addr,
		},
	}
}

func (this *KeyServer) Start() error {
	return this.server.ListenAndServe()
}
