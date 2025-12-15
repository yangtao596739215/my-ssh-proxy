package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"my-ssh-proxy/pkg/keyring"
	"my-ssh-proxy/pkg/relay"
)

func main() {
	port := flag.Int("port", 2222, "SSH listen port")
	socketDir := flag.String("socket-dir", "/tmp/my-ssh-proxy", "Directory to host streamlocal sockets")
	flag.Parse()

	if err := os.MkdirAll(*socketDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir socket-dir: %v\n", err)
		os.Exit(1)
	}

	hostSigner, _, err := keyring.EnsureKeyPair(keyring.HostKeyName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "host signer: %v\n", err)
		os.Exit(1)
	}

	// 从 known_hosts 读取授权公钥列表（全部条目作为白名单）。
	authorizedKeys, err := loadKnownHostsKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load known_hosts: %v\n", err)
		os.Exit(1)
	}
	if len(authorizedKeys) == 0 {
		fmt.Fprintf(os.Stderr, "known_hosts empty: provide at least one key\n")
		os.Exit(1)
	}
	directAuthorized := map[string][]gossh.PublicKey{"direct": authorizedKeys}
	proxyAuthorized := map[string][]gossh.PublicKey{"proxy": authorizedKeys}

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}

	s, err := relay.New(relay.Config{
		Addr:                 fmt.Sprintf("0.0.0.0:%d", *port),
		SocketDir:            *socketDir,
		HostKey:              hostSigner,
		DirectAuthorizedKeys: directAuthorized,
		ProxyAuthorizedKeys:  proxyAuthorized,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init relay: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := s.Serve(ctx, ln); err != nil {
		fmt.Fprintf(os.Stderr, "server run: %v\n", err)
		os.Exit(1)
	}
}

// loadKnownHostsKeys 读取 ~/.ssh/known_hosts 的所有公钥作为允许列表。
func loadKnownHostsKeys() ([]gossh.PublicKey, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := home + "/.ssh/known_hosts"
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var keys []gossh.PublicKey
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		keyStr := strings.Join(fields[1:3], " ")
		pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(keyStr))
		if err != nil || pub == nil {
			continue
		}
		m := string(pub.Marshal())
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		keys = append(keys, pub)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}
