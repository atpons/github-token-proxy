package gh

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	DefaultEndpoint = "https://api.github.com"
)

type InstallationResponse struct {
	ID int `json:"id"`
}

type InstallationAccessTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Authenticator struct {
	endpoint   string
	appId      string
	privateKey *rsa.PrivateKey
	client     *http.Client
}

func (a *Authenticator) GetToken(owner, repo string) (string, error) {
	signature, err := a.GenerateJWT()
	if err != nil {
		return "", errors.Wrap(err, "failed to get token")
	}

	installationID, err := a.GetInstallationID(owner, repo, signature)
	if err != nil {
		return "", errors.Wrap(err, "failed to get installation id")
	}

	token, err := a.GetInstallationToken(installationID, signature)
	if err != nil {
		return "", errors.Wrap(err, "failed to get installation token")
	}

	return token, nil
}

func (a *Authenticator) CreateRequestWithJWT(method string, requestPath string, body io.Reader, token []byte) (*http.Request, error) {
	requestPath, _ = url.JoinPath(a.endpoint, requestPath)
	req, err := http.NewRequest(method, requestPath, body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	return req, nil
}

func (a *Authenticator) GetInstallationID(owner string, repo string, token []byte) (int, error) {
	req, err := a.CreateRequestWithJWT("GET", "/repos/"+owner+"/"+repo+"/installation", nil, token)
	fmt.Println(owner, repo, string(token))
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	var installationResponse InstallationResponse
	if err := json.NewDecoder(resp.Body).Decode(&installationResponse); err != nil {
		return 0, errors.Wrap(err, "failed to decode response")
	}

	fmt.Println(installationResponse.ID)

	return installationResponse.ID, nil
}

func (a *Authenticator) GetInstallationToken(installationID int, token []byte) (string, error) {
	req, err := a.CreateRequestWithJWT("POST", fmt.Sprintf("/app/installations/%d/access_tokens", installationID), nil, token)
	if err != nil {
		return "", errors.Wrap(err, "failed to create request")
	}

	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	var tokenResponse InstallationAccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", errors.Wrap(err, "failed to decode response")
	}

	return tokenResponse.Token, nil
}

func (a *Authenticator) GenerateJWT() ([]byte, error) {
	t := jwt.New()
	_ = t.Set(jwt.IssuerKey, a.appId)
	_ = t.Set(jwt.IssuedAtKey, time.Now())
	_ = t.Set(jwt.ExpirationKey, time.Now().Add(10*time.Minute))

	signed, err := jwt.Sign(t, jwa.RS256, a.privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign jwt")
	}

	return signed, err
}

func BuildGitHubCloudAuthenticator(appID string, privateKey *rsa.PrivateKey) *Authenticator {
	return &Authenticator{
		endpoint:   DefaultEndpoint,
		appId:      appID,
		privateKey: privateKey,
		client:     &http.Client{},
	}
}

func PrivateKeyFromFile(filepath string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read file")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.Wrap(err, "failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse RSA private key")
	}

	return privateKey, nil
}
