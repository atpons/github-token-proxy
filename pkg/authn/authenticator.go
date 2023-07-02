package authn

import (
	"net/http"
)

type Result struct {
	Requester string `json:"requester"`
}

type Authenticator interface {
	Auth(req *http.Request) (*Result, error)
}
