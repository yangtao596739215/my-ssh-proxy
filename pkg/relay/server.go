package relay

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"my-ssh-proxy/pkg/protocol"
)

// Config controls how the relay server authenticates and where it exposes sockets.
type Config struct {
	Addr      string
	SocketDir string

	// HostKey is the SSH host identity.
	HostKey gossh.Signer

	// Authorized public keys for each role.
	DirectAuthorizedKeys map[string][]gossh.PublicKey
	ProxyAuthorizedKeys  map[string][]gossh.PublicKey
	IdleTimeout          time.Duration
	KeepAliveInterval    time.Duration
}

// Server implements a lightweight SSH relay that lets backend agents expose a
// Unix socket, and lets direct SSH clients reach that socket with standard
// streamlocal forwarding (-L localPort:/path/to/socket).
type Server struct {
	cfg Config

	mu            sync.RWMutex
	directK       map[string][]gossh.PublicKey
	proxyK        map[string][]gossh.PublicKey
	backendSocket map[string]string // backend_key -> unix socket path
}

// New creates a new relay server.
func New(cfg Config) (*Server, error) {
	if cfg.HostKey == nil {
		return nil, fmt.Errorf("HostKey required")
	}
	if cfg.SocketDir == "" {
		cfg.SocketDir = "/tmp/my-ssh-proxy"
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.KeepAliveInterval == 0 {
		cfg.KeepAliveInterval = 30 * time.Second
	}
	s := &Server{
		cfg:           cfg,
		directK:       make(map[string][]gossh.PublicKey),
		proxyK:        make(map[string][]gossh.PublicKey),
		backendSocket: make(map[string]string),
	}

	// seed initial keys
	for user, keys := range cfg.DirectAuthorizedKeys {
		s.directK[user] = append([]gossh.PublicKey(nil), keys...)
	}
	for user, keys := range cfg.ProxyAuthorizedKeys {
		s.proxyK[user] = append([]gossh.PublicKey(nil), keys...)
	}

	return s, nil
}

// Serve starts accepting SSH connections on the provided listener.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

	sshCfg := &gossh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
	}
	sshCfg.AddHostKey(s.cfg.HostKey)

	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0

		go s.handleConn(ctx, conn, sshCfg)
	}
}

func (s *Server) publicKeyCallback(meta gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
	switch meta.User() {
	case "direct", "proxy":
		return &gossh.Permissions{
			Extensions: map[string]string{"user": meta.User()},
		}, nil
	default:
		return nil, fmt.Errorf("unauthorized user %s", meta.User())
	}
}

func (s *Server) handleConn(ctx context.Context, rawConn net.Conn, sshCfg *gossh.ServerConfig) {
	defer rawConn.Close()

	sshConn, chans, reqs, err := gossh.NewServerConn(rawConn, sshCfg)
	if err != nil {
		log.Printf("[server] ssh handshake failed: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("[server] new connection from=%s user=%s", sshConn.RemoteAddr(), sshConn.User())

	user := sshConn.User()
	switch user {
	case "proxy":
		s.handleProxyConn(ctx, sshConn, chans, reqs)
	case "direct":
		s.handleDirectConn(ctx, sshConn, chans, reqs)
	default:
		sshConn.Close()
	}
}

func (s *Server) handleProxyConn(ctx context.Context, conn *gossh.ServerConn, chans <-chan gossh.NewChannel, reqs <-chan *gossh.Request) {
	// Backend agents never open channels proactively; they register a remote forward.
	go func() {
		for ch := range chans {
			ch.Reject(gossh.UnknownChannelType, "proxy does not accept channels")
		}
	}()

	listeners := make(map[string]net.Listener)
	var mu sync.Mutex

	defer func() {
		mu.Lock()
		for _, l := range listeners {
			l.Close()
		}
		mu.Unlock()
	}()

	for req := range reqs {
		switch req.Type {
		case protocol.UpdateAuthKeyRequestType:
			ok := s.handleUpdateKey(req)
			log.Printf("[server] proxy update-authorized-key user=%s ok=%v", conn.User(), ok)
			req.Reply(ok, nil)
			continue
		case protocol.ForwardRequestType:
			// handled below
		default:
			log.Printf("[server] proxy unknown request type=%s from=%s", req.Type, conn.RemoteAddr())
			req.Reply(false, nil)
			continue
		}

		var payload protocol.RemoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &payload); err != nil || payload.BindUnixSocket == "" {
			req.Reply(false, nil)
			continue
		}

		backendKey := payload.BindUnixSocket
		socketPath := filepath.Join(s.cfg.SocketDir, backendKey+".sock")

		// Ensure directory exists.
		if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
			req.Reply(false, nil)
			continue
		}
		// Clean up old socket if present.
		_ = os.Remove(socketPath)

		l, err := net.Listen("unix", socketPath)
		if err != nil {
			log.Printf("[server] proxy backend-key=%s listen unix failed: %v", backendKey, err)
			req.Reply(false, nil)
			continue
		}

		mu.Lock()
		listeners[socketPath] = l
		mu.Unlock()

		// 记录 backend_key 到 socket 的映射，供 direct 侧查找。
		s.mu.Lock()
		s.backendSocket[backendKey] = socketPath
		s.mu.Unlock()

		log.Printf("[server] proxy registered backend-key=%s socket=%s from=%s", backendKey, socketPath, conn.RemoteAddr())

		req.Reply(true, nil)

		go s.acceptUnix(ctx, conn, socketPath, l)
	}
}

func (s *Server) handleDirectConn(ctx context.Context, conn *gossh.ServerConn, chans <-chan gossh.NewChannel, reqs <-chan *gossh.Request) {
	go func() {
		for req := range reqs {
			if req.Type == protocol.UpdateAuthKeyRequestType {
				ok := s.handleUpdateKey(req)
				log.Printf("[server] direct update-authorized-key user=%s ok=%v", conn.User(), ok)
				_ = req.Reply(ok, nil)
				continue
			}
			log.Printf("[server] direct unknown request type=%s from=%s", req.Type, conn.RemoteAddr())
			req.Reply(false, nil)
		}
	}()
	for newCh := range chans {
		if newCh.ChannelType() != "direct-streamlocal@openssh.com" {
			log.Printf("[server] direct reject channel type=%s from=%s", newCh.ChannelType(), conn.RemoteAddr())
			newCh.Reject(gossh.UnknownChannelType, "unsupported channel")
			continue
		}
		var payload struct {
			SocketPath string
			Reserved   string
		}
		if err := gossh.Unmarshal(newCh.ExtraData(), &payload); err != nil || payload.SocketPath == "" {
			newCh.Reject(gossh.Prohibited, "bad payload")
			continue
		}

		backendKey := payload.SocketPath

		s.mu.RLock()
		socketPath, ok := s.backendSocket[backendKey]
		s.mu.RUnlock()
		if !ok {
			log.Printf("[server] direct backend-key not found key=%s from=%s", backendKey, conn.RemoteAddr())
			newCh.Reject(gossh.ConnectionFailed, "unknown backend key")
			continue
		}

		targetConn, err := net.Dial("unix", socketPath)
		if err != nil {
			log.Printf("[server] direct backend-key=%s dial unix %s failed: %v", backendKey, socketPath, err)
			newCh.Reject(gossh.ConnectionFailed, err.Error())
			continue
		}

		ch, reqs, err := newCh.Accept()
		if err != nil {
			targetConn.Close()
			log.Printf("[server] direct accept channel failed backend-key=%s: %v", backendKey, err)
			continue
		}
		go gossh.DiscardRequests(reqs)

		log.Printf("[server] direct channel established backend-key=%s from=%s", backendKey, conn.RemoteAddr())
		go proxyConn(ctx, ch, targetConn)
	}
}

func (s *Server) acceptUnix(ctx context.Context, serverConn *gossh.ServerConn, socketPath string, l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}

		go func(c net.Conn) {
			defer c.Close()
			ch, reqs, err := serverConn.OpenChannel(protocol.ForwardedRequestType, gossh.Marshal(&protocol.RemoteForwardRequest{BindUnixSocket: socketPath}))
			if err != nil {
				log.Printf("[server] open forwarded channel to backend failed socket=%s: %v", socketPath, err)
				return
			}
			go gossh.DiscardRequests(reqs)
			log.Printf("[server] forwarded channel opened socket=%s backend-addr=%s", socketPath, serverConn.RemoteAddr())
			proxyConn(ctx, ch, c)
		}(conn)
	}
}

func proxyConn(ctx context.Context, a io.ReadWriteCloser, b io.ReadWriteCloser) {
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

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// keysEqual compares two ssh public keys in constant time on their marshaled form.
func keysEqual(a, b gossh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	ab := a.Marshal()
	bb := b.Marshal()
	if len(ab) != len(bb) {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// handleUpdateKey parses and stores a new authorized key for the given user.
// It returns true on success.
func (s *Server) handleUpdateKey(req *gossh.Request) bool {
	var payload protocol.UpdateAuthKeyRequest
	if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
		return false
	}
	if payload.User == "" || strings.TrimSpace(payload.AuthorizedKey) == "" {
		log.Printf("[server] update-authorized-key invalid payload user='%s'", payload.User)
		return false
	}
	key, _, _, _, err := gossh.ParseAuthorizedKey([]byte(payload.AuthorizedKey))
	if err != nil {
		log.Printf("[server] update-authorized-key parse key failed user=%s: %v", payload.User, err)
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target := s.directK
	if payload.User == "proxy" {
		target = s.proxyK
	}

	existing := target[payload.User]
	for _, k := range existing {
		if keysEqual(k, key) {
			log.Printf("[server] update-authorized-key user=%s: key already exists", payload.User)
			return true // already present
		}
	}
	target[payload.User] = append(existing, key)
	log.Printf("[server] update-authorized-key user=%s: key added, total=%d", payload.User, len(target[payload.User]))
	return true
}

func (s *Server) storeKey(user string, key gossh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.directK
	if user == "proxy" {
		target = s.proxyK
	}
	target[user] = append(target[user], key)
}
