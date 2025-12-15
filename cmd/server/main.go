package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	gossh "golang.org/x/crypto/ssh"

	"my-ssh-proxy/pkg/keyring"
	"my-ssh-proxy/pkg/relay"
)

func main() {
	port := flag.Int("port", 2222, "SSH listen port")
	socketDir := flag.String("socket-dir", "/tmp/my-ssh-proxy", "Directory to host streamlocal sockets")
	allowBootstrap := flag.Bool("allow-bootstrap", false, "Allow first-connection key bootstrap when no key is present for the user")
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

	directAuthorized := make(map[string][]gossh.PublicKey)
	proxyAuthorized := make(map[string][]gossh.PublicKey)
	if !*allowBootstrap {
		directPub, err := keyring.PublicKey(keyring.DirectKeyName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load direct public key: %v\n", err)
			os.Exit(1)
		}
		proxyPub, err := keyring.PublicKey(keyring.ProxyKeyName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load proxy public key: %v\n", err)
			os.Exit(1)
		}
		directAuthorized["direct"] = []gossh.PublicKey{directPub}
		proxyAuthorized["proxy"] = []gossh.PublicKey{proxyPub}
	}

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
		AllowBootstrap:       *allowBootstrap,
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
