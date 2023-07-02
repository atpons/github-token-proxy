package main

import (
	"os"

	"github.com/atpons/github-token-proxy/pkg/authn"
	"github.com/atpons/github-token-proxy/pkg/gh"
	"github.com/atpons/github-token-proxy/pkg/router"
	"golang.org/x/exp/slog"
)

func main() {
	p := os.Getenv("GITHUB_PUBLIC_KEY_PATH")
	appId := os.Getenv("GITHUB_APP_ID")

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	pkey, err := gh.PrivateKeyFromFile(p)

	if err != nil {
		panic(err)
	}

	client := gh.BuildGitHubCloudClient(appId, pkey, logger)

	pubKeyPath := os.Getenv("PUBLIC_KEY_PATH")

	pubKey, err := authn.LoadSSHPublicKey(pubKeyPath)

	if err != nil {
		panic(err)
	}

	authenticator, err := authn.BuildJWTAuthenticator(*pubKey)

	if err != nil {
		panic(err)
	}

	api := router.NewHandler(client, authenticator, logger)

	api.Start()
}
