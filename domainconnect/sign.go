package domainconnect

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Signer signs apply requests with the service's private key, which is how a
// DNS provider knows the variables in the address were not made up by somebody
// else. The provider reads the public key from a TXT record in the template's
// syncPubKeyDomain, at the host KeyHost.
type Signer struct {
	key     *rsa.PrivateKey
	keyHost string
}

// NewSigner reads an RSA private key in PEM, PKCS#8 or PKCS#1. keyHost is the
// host of the TXT record that holds the public key, such as "_dck1", and
// travels with every request so the key can be rotated.
func NewSigner(privatePEM []byte, keyHost string) (*Signer, error) {
	keyHost = strings.TrimSpace(keyHost)
	if keyHost == "" || strings.ContainsAny(keyHost, " &=?#/") {
		return nil, errors.New("domainconnect: the key host is empty or not a host label")
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, errors.New("domainconnect: the private key is not PEM")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("domainconnect: the private key is not RSA")
		}
		key = rsaKey
	} else if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = rsaKey
	} else {
		return nil, errors.New("domainconnect: the private key could not be read")
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("domainconnect: the private key is shorter than 2048 bits")
	}
	return &Signer{key: key, keyHost: keyHost}, nil
}

// KeyHost is the host of the public key's TXT record.
func (s *Signer) KeyHost() string { return s.keyHost }

// Sign answers the base64 RSA-SHA256 signature of a query string.
func (s *Signer) Sign(query string) (string, error) {
	sum := sha256.Sum256([]byte(query))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("domainconnect: signing: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// PublicKeyRecords answers the TXT values to publish at KeyHost in the
// template's syncPubKeyDomain, one per record and each short enough for a DNS
// server that limits the size of a TXT record: "p=1,a=RS256,d=...".
func (s *Signer) PublicKeyRecords() ([]string, error) {
	der, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("domainconnect: encoding the public key: %w", err)
	}
	return publicKeyRecords(base64.StdEncoding.EncodeToString(der)), nil
}

func publicKeyRecords(encoded string) []string {
	const chunk = 200
	var out []string
	for part := 1; len(encoded) > 0; part++ {
		n := min(chunk, len(encoded))
		out = append(out, fmt.Sprintf("p=%d,a=RS256,d=%s", part, encoded[:n]))
		encoded = encoded[n:]
	}
	return out
}

// GenerateKey makes a 2048-bit RSA private key in PKCS#8 PEM, for a service
// that is signing for the first time.
func GenerateKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("domainconnect: generating a key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("domainconnect: encoding the key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
