package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"path/filepath"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"my-ssh-proxy/pkg/keyring"
)

func main() {
	serverAddr := flag.String("server", "127.0.0.1:2222", "SSH server address")
	backendKey := flag.String("backend-key", "", "Backend key to connect to")
	listenAddr := flag.String("listen", "127.0.0.1:9000", "Local address to expose for clients")
	flag.Parse()

	if strings.TrimSpace(*backendKey) == "" {
		fmt.Fprintln(os.Stderr, "backend-key required")
		os.Exit(1)
	}

	log.Printf("[client] starting server=%s backend-key=%s listen=%s", *serverAddr, *backendKey, *listenAddr)

	signer, _, err := keyring.LoadDefaultSigner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load default key: %v\n", err)
		os.Exit(1)
	}
	log.Printf("[client] loaded key path=~/.ssh/id_rsa(.pub)")

	cb, err := loadKnownHostsCallback()
	if err != nil {
		fmt.Fprintf(os.Stderr, "known_hosts: %v\n", err)
		os.Exit(1)
	}

	cfg := &gossh.ClientConfig{
		User:            "direct",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: cb,
	}

	client, err := gossh.Dial("tcp", *serverAddr, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial ssh server: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	log.Printf("[client] connected to server=%s", *serverAddr)

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen %s: %v\n", *listenAddr, err)
		os.Exit(1)
	}
	defer ln.Close()
	log.Printf("[client] listening on %s -> backend-key=%s via %s", *listenAddr, *backendKey, *serverAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		<-stop
		close(done)
		ln.Close()
		client.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				log.Printf("[client] exit")
				return
			default:
				fmt.Fprintf(os.Stderr, "accept local: %v\n", err)
				log.Printf("[client] accept local failed: %v", err)
				continue
			}
		}
		log.Printf("[client] new local connection from=%s", conn.RemoteAddr())
		go handleLocalConn(conn, client, *backendKey)
	}
}

func handleLocalConn(local net.Conn, client *gossh.Client, socketPath string) {
	defer local.Close()
	payload := gossh.Marshal(&struct {
		SocketPath string
		Reserved   string
	}{
		SocketPath: socketPath,
	})
	ch, reqs, err := client.OpenChannel("direct-streamlocal@openssh.com", payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open remote channel: %v\n", err)
		log.Printf("[client] open remote channel failed backend-key=%s: %v", socketPath, err)
		return
	}
	go gossh.DiscardRequests(reqs)
	log.Printf("[client] remote channel established backend-key=%s local=%s server=%s", socketPath, local.RemoteAddr(), client.Conn.RemoteAddr())
	proxyIO(local, ch)
}

func proxyIO(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

func loadKnownHostsCallback() (gossh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, keyring.DefaultKnownHosts)
	return knownhosts.New(path)
}
