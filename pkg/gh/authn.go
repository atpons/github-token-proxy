package gh

import (
	"context"
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

	"github.com/atpons/github-token-proxy/pkg/constant"
	"github.com/cockroachdb/errors"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/exp/slog"
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

type Client struct {
	endpoint   string
	appId      string
	privateKey *rsa.PrivateKey
	client     *http.Client
	logger     *slog.Logger
}

func (c *Client) GetToken(ctx context.Context, owner, repo string) (string, error) {
	signature, err := c.GenerateJWT()
	if err != nil {
		return "", errors.Wrap(err, "failed to get token")
	}

	installationID, err := c.GetInstallationID(ctx, owner, repo, signature)
	if err != nil {
		return "", errors.Wrap(err, "failed to get installation id")
	}

	token, err := c.GetInstallationToken(ctx, installationID, signature)
	if err != nil {
		return "", errors.Wrap(err, "failed to get installation token")
	}

	return token, nil
}

func (c *Client) CreateRequestWithJWT(ctx context.Context, method string, requestPath string, body io.Reader, token []byte) (*http.Request, error) {
	requestPath, _ = url.JoinPath(c.endpoint, requestPath)
	req, err := http.NewRequest(method, requestPath, body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "github-token-proxy")
	return req.WithContext(ctx), nil
}

func (c *Client) GetInstallationID(ctx context.Context, owner string, repo string, token []byte) (int, error) {
	req, err := c.CreateRequestWithJWT(ctx, "GET", "/repos/"+owner+"/"+repo+"/installation", nil, token)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	var installationResponse InstallationResponse
	if err := json.NewDecoder(resp.Body).Decode(&installationResponse); err != nil {
		return 0, errors.Wrap(err, "failed to decode response")
	}

	return installationResponse.ID, nil
}

func (c *Client) GetInstallationToken(ctx context.Context, installationID int, token []byte) (string, error) {
	req, err := c.CreateRequestWithJWT(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", installationID), nil, token)
	if err != nil {
		return "", errors.Wrap(err, "failed to create request")
	}

	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.client.Do(req)
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

func (c *Client) GenerateJWT() ([]byte, error) {
	t := jwt.New()
	_ = t.Set(jwt.IssuerKey, c.appId)
	_ = t.Set(jwt.IssuedAtKey, time.Now())
	_ = t.Set(jwt.ExpirationKey, time.Now().Add(10*time.Minute))

	signed, err := jwt.Sign(t, jwa.RS256, c.privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign jwt")
	}

	return signed, err
}

type Transport struct {
	internal http.RoundTripper
	logger   *slog.Logger
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.internal.RoundTrip(req)

	if err != nil {
		return resp, err
	}

	ctx := resp.Request.Context()

	var reqId string

	if rid, ok := ctx.Value(constant.RequestIdContextKey).(string); ok {
		reqId = rid
	}

	t.logger.Info("github request complete",
		slog.Int("code", resp.StatusCode),
		slog.String("url", resp.Request.URL.String()),
		slog.String("request_id", reqId),
	)

	return resp, err
}

func BuildGitHubCloudClient(appID string, privateKey *rsa.PrivateKey, logger *slog.Logger) *Client {
	return &Client{
		endpoint:   DefaultEndpoint,
		appId:      appID,
		privateKey: privateKey,
		client: &http.Client{
			Transport: &Transport{
				internal: http.DefaultTransport,
				logger:   logger,
			},
		},
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
