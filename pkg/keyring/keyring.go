package keyring

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

const (
	// HostKeyName is the key name used by the relay server as SSH host identity.
	HostKeyName = "host"
	// DirectKeyName is the key name used by direct (client-facing) agents.
	DirectKeyName = "direct"
	// ProxyKeyName is the key name used by backend proxy agents.
	ProxyKeyName = "proxy"
)

const (
	privateSuffix = ".key"
	publicSuffix  = ".pub"
	marker        = "myproxy-ed25519"
)

// EnsureKeyPair makes sure the named key pair exists under ~/.ssh/myproxy and
// returns the signer plus its authorized-key bytes (RFC4253 format).
func EnsureKeyPair(name string) (gossh.Signer, []byte, error) {
	dir, err := ensureBaseDir()
	if err != nil {
		return nil, nil, err
	}
	privPath := filepath.Join(dir, name+privateSuffix)
	pubPath := filepath.Join(dir, name+publicSuffix)

	var signer gossh.Signer
	if _, err := os.Stat(privPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("stat private key %s: %w", privPath, err)
		}
		signer, err = generateAndStore(privPath, pubPath)
		if err != nil {
			return nil, nil, err
		}
	} else {
		signer, err = loadSigner(privPath)
		if err != nil {
			return nil, nil, err
		}
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			pubBytes = gossh.MarshalAuthorizedKey(signer.PublicKey())
			if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
				return nil, nil, fmt.Errorf("write public key %s: %w", pubPath, err)
			}
		} else {
			return nil, nil, fmt.Errorf("read public key %s: %w", pubPath, err)
		}
	}

	return signer, pubBytes, nil
}

// PublicKey ensures the key exists and returns the parsed ssh.PublicKey.
func PublicKey(name string) (gossh.PublicKey, error) {
	_, auth, err := EnsureKeyPair(name)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey(auth)
	if err != nil {
		return nil, fmt.Errorf("parse authorized key for %s: %w", name, err)
	}
	return pub, nil
}

func ensureBaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	dir := filepath.Join(home, ".ssh", "myproxy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return dir, nil
}

func generateAndStore(privPath, pubPath string) (gossh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	if err := writePrivate(privPath, priv); err != nil {
		return nil, err
	}
	pubBytes := gossh.MarshalAuthorizedKey(signer.PublicKey())
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}
	return signer, nil
}

func writePrivate(path string, priv ed25519.PrivateKey) error {
	payload := fmt.Sprintf("%s %s\n", marker, base64.StdEncoding.EncodeToString(priv))
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		return fmt.Errorf("write private key %s: %w", path, err)
	}
	return nil
}

func loadSigner(path string) (gossh.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	enc := strings.TrimSpace(string(raw))
	parts := strings.Fields(enc)
	if len(parts) == 2 && parts[0] == marker {
		enc = parts[1]
	}
	buf, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("decode private key %s: %w", path, err)
	}
	if len(buf) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key %s has invalid size %d", path, len(buf))
	}
	priv := ed25519.PrivateKey(buf)
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("signer from %s: %w", path, err)
	}
	return signer, nil
}
