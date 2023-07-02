package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/atpons/github-token-proxy/pkg/authn"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	DefaultPrivateKeyPath = ".ssh/id_rsa"
)

type GitCredentials struct {
	Protocol string
	Host     string
}

type TokenResponse struct {
	Token string `json:"token"`
}

func main() {
	org := flag.String("org", "", "GitHub organization")
	repo := flag.String("repo", "", "GitHub repo")

	flag.Parse()

	pkeyPath := os.Getenv("PRIVATE_KEY_PATH")

	if pkeyPath == "" {
		hdir, _ := os.UserHomeDir()
		pkeyPath = path.Join(hdir, DefaultPrivateKeyPath)
	}

	privateKeyBytes, err := os.ReadFile(pkeyPath)
	if err != nil {
		log.Fatalf("Error reading private key: %v", err)
	}
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		log.Fatal("Failed to decode PEM block containing private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}

	token := authn.BuildJWT()

	signedToken, err := jwt.Sign(token, jwa.RS256, privateKey)
	if err != nil {
		log.Fatalf("Error signing token: %v", err)
	}

	credentials := GitCredentials{}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid input: %s\n", line)
			continue
		}

		key, value := parts[0], parts[1]

		switch key {
		case "protocol":
			credentials.Protocol = value
		case "host":
			credentials.Host = value
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
	}

	if credentials.Host == "github.com" && credentials.Protocol == "https" {
		client := &http.Client{}
		req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:8080/client?owner=%s&repo=%s", *org, *repo), nil)
		if err != nil {
			log.Fatalf("Error creating request: %v", err)
		}

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(signedToken)))

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Error making request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading response body: %v", err)
		}

		tres := &TokenResponse{}

		if err := json.Unmarshal(body, tres); err != nil {
			panic(err)
		}

		fmt.Printf("username=x-oauth-basic\n")
		fmt.Printf("password=%s\n", tres.Token)
	}
}
