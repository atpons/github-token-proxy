package authn

import (
	"crypto/rsa"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/crypto/ssh"
)

type JWTAuthenticator struct {
	PublicKey rsa.PublicKey
}

func BuildJWTAuthenticator(publicKey rsa.PublicKey) (*JWTAuthenticator, error) {
	return &JWTAuthenticator{
		PublicKey: publicKey,
	}, nil
}

func LoadSSHPublicKey(fpath string) (*rsa.PublicKey, error) {
	sshPublicKey, err := os.ReadFile(fpath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read public key file")
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(sshPublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse SSH public key")
	}

	parsedCryptoPublicKey := pubKey.(ssh.CryptoPublicKey)

	cryptoPublicKey := parsedCryptoPublicKey.CryptoPublicKey()

	rsaPubKey, ok := cryptoPublicKey.(*rsa.PublicKey)

	if !ok {
		return nil, errors.New("failed to type casting for rsa.PublicKey")
	}

	return rsaPubKey, nil
}

func (a *JWTAuthenticator) Auth(req *http.Request) (*Result, error) {
	token := req.Header.Get("Authorization")
	if token == "" {
		return nil, errors.New("authorization header is empty value")
	}

	ts := strings.TrimPrefix(token, "Bearer ")

	t, err := a.Verify(ts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify token")
	}

	return &Result{Requester: t.Subject()}, nil
}

func (a *JWTAuthenticator) Verify(token string) (jwt.Token, error) {
	t, err := jwt.ParseString(token, jwt.WithVerify(jwa.RS256, a.PublicKey))
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse jwt")
	}

	return t, nil
}

func BuildJWT() jwt.Token {
	token := jwt.New()
	_ = token.Set(jwt.IssuedAtKey, time.Now())
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	_ = token.Set(jwt.SubjectKey, hostname)
	return token
}
