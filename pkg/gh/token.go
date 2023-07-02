package gh

import (
	"crypto/sha256"
	"encoding/base64"
)

func ConvertTokenToDiscoverableHash(token string) string {
	s := sha256.New()
	s.Write([]byte(token))
	hash := s.Sum(nil)
	return base64.StdEncoding.EncodeToString(hash[:])
}
