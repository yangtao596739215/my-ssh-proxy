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

	gossh "golang.org/x/crypto/ssh"

	"my-ssh-proxy/pkg/keyring"
	"my-ssh-proxy/pkg/protocol"
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

	signer, authorized, err := keyring.EnsureKeyPair(keyring.DirectKeyName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load direct key: %v\n", err)
		os.Exit(1)
	}
	log.Printf("[client] loaded key path=~/.ssh/myproxy/%s.*", keyring.DirectKeyName)

	cfg := &gossh.ClientConfig{
		User:            "direct",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	client, err := gossh.Dial("tcp", *serverAddr, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial ssh server: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	log.Printf("[client] connected to server=%s", *serverAddr)

	if err := pushAuthorizedKey(client, "direct", strings.TrimSpace(string(authorized))); err != nil {
		fmt.Fprintf(os.Stderr, "update authorized key: %v\n", err)
		log.Printf("[client] update-authorized-key failed: %v", err)
	} else {
		log.Printf("[client] update-authorized-key success user=direct")
	}

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

func pushAuthorizedKey(client *gossh.Client, user string, authorized string) error {
	payload := gossh.Marshal(&protocol.UpdateAuthKeyRequest{
		User:          user,
		AuthorizedKey: authorized,
	})
	ok, _, err := client.SendRequest(protocol.UpdateAuthKeyRequestType, true, payload)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("server rejected update authorization request")
	}
	return nil
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
