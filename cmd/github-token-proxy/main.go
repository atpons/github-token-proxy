package main

import (
	"os"

	"github.com/atpons/github-token-proxy/pkg/gh"
	"github.com/atpons/github-token-proxy/pkg/router"
	"golang.org/x/exp/slog"
)

func main() {
	p := os.Getenv("GITHUB_PUBLIC_KEY_PATH")
	appId := os.Getenv("GITHUB_APP_ID")

	pkey, err := gh.PrivateKeyFromFile(p)

	if err != nil {
		panic(err)
	}

	authn := gh.BuildGitHubCloudAuthenticator(appId, pkey)

	api := router.NewHandler(authn, slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	api.Start()
}
