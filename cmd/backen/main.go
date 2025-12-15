package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strings"
	"syscall"

	gossh "golang.org/x/crypto/ssh"

	"my-ssh-proxy/pkg/keyring"
	"my-ssh-proxy/pkg/protocol"

	// pty support

	pty "github.com/creack/pty"
	"github.com/pkg/sftp"
)

func main() {
	serverAddr := flag.String("server", "127.0.0.1:2222", "SSH server address")
	user := flag.String("user", "proxy", "SSH user for backend registration")
	localTarget := flag.String("local", "127.0.0.1:9000", "Local target to forward to")
	enableLocalSSH := flag.Bool("sshserver", false, "Start a local ssh server on -local for testing (basic shell, public-key auth)")
	flag.Parse()

	backendKey := mustRandomKey()

	log.Printf("[backen] starting server=%s user=%s backend-key=%s local=%s sshserver=%v", *serverAddr, *user, backendKey, *localTarget, *enableLocalSSH)

	signer, authorized, err := keyring.EnsureKeyPair(keyring.ProxyKeyName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load proxy key: %v\n", err)
		os.Exit(1)
	}
	log.Printf("[backen] loaded key path=~/.ssh/myproxy/%s.*", keyring.ProxyKeyName)

	cfg := &gossh.ClientConfig{
		User:            *user,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	client, err := gossh.Dial("tcp", *serverAddr, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial ssh server: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	log.Printf("[backen] connected to server=%s", *serverAddr)

	// Push our public key to server so it can accept future connections.
	pubKey := strings.TrimSpace(string(authorized))
	updatePayload := gossh.Marshal(&protocol.UpdateAuthKeyRequest{
		User:          *user,
		AuthorizedKey: pubKey,
	})
	ok, _, err := client.SendRequest(protocol.UpdateAuthKeyRequestType, true, updatePayload)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "update authorized key failed: ok=%v err=%v\n", ok, err)
		log.Printf("[backen] update-authorized-key failed ok=%v err=%v", ok, err)
		// not fatal; continue
	} else {
		log.Printf("[backen] update-authorized-key success user=%s", *user)
	}

	// Request remote streamlocal forward
	payload := gossh.Marshal(&protocol.RemoteForwardRequest{BindUnixSocket: backendKey})
	ok, _, err = client.SendRequest(protocol.ForwardRequestType, true, payload)
	if err != nil || !ok {
		fmt.Fprintf(os.Stderr, "request streamlocal forward failed: ok=%v err=%v\n", ok, err)
		os.Exit(1)
	}
	log.Printf("[backen] registered backend-key=%s -> local=%s via server=%s", backendKey, *localTarget, *serverAddr)

	if *enableLocalSSH {
		go func() {
			if err := startLocalSSH(*localTarget); err != nil {
				log.Printf("[backen] local ssh server error: %v", err)
			}
		}()
	}

	// Handle forwarded connections coming back as channels
	chans := client.HandleChannelOpen(protocol.ForwardedRequestType)
	go func() {
		for newCh := range chans {
			go func(nc gossh.NewChannel) {
				log.Printf("[backen] incoming forwarded channel backend-key=%s from=%s", backendKey, client.Conn.RemoteAddr())
				ch, reqs, err := nc.Accept()
				if err != nil {
					fmt.Fprintf(os.Stderr, "accept channel: %v\n", err)
					log.Printf("[backen] accept forwarded channel failed: %v", err)
					return
				}
				go gossh.DiscardRequests(reqs)

				targetConn, err := net.Dial("tcp", *localTarget)
				if err != nil {
					fmt.Fprintf(os.Stderr, "dial local %s: %v\n", *localTarget, err)
					log.Printf("[backen] dial local failed addr=%s err=%v", *localTarget, err)
					ch.Close()
					return
				}
				log.Printf("[backen] forwarding started backend-key=%s remote=%s -> local=%s", backendKey, client.Conn.RemoteAddr(), *localTarget)

				// bidirectional copy
				go func() {
					defer ch.Close()
					defer targetConn.Close()
					_, _ = ioCopy(ch, targetConn)
				}()
				go func() {
					defer ch.Close()
					defer targetConn.Close()
					_, _ = ioCopy(targetConn, ch)
				}()
			}(newCh)
		}
	}()

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("exit")
}

// ioCopy is a thin wrapper to avoid importing the full io.Copy twice.
func ioCopy(dst io.ReadWriteCloser, src io.ReadWriteCloser) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, fmt.Errorf("short write")
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

func mustRandomKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return strings.TrimRight(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]), "=")
}

// startLocalSSH 启动一个简易 SSH 服务器，监听在 localTarget 指定的 host:port，供本地测试。
// 仅支持公钥认证；授权公钥来源：
//  1. 当前用户 ~/.ssh/id_*.pub（若存在）
//  2. myproxy 的 direct/proxy 公钥（若存在）
//
// shell：使用 /bin/sh，接受 session channel 的 shell 请求；简单应答 pty-req/exec/env。
func startLocalSSH(localTarget string) error {
	host, port, err := net.SplitHostPort(localTarget)
	if err != nil {
		return fmt.Errorf("parse local target: %w", err)
	}
	if host == "" {
		host = "127.0.0.1"
	}

	hostSigner, _, err := keyring.EnsureKeyPair("backend-sshd-host")
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	authorized := loadAuthorizedKeys()
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(c gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			for _, k := range authorized {
				if keysEqual(k, key) {
					log.Printf("[backen-sshd] auth ok user=%s remote=%s", c.User(), c.RemoteAddr())
					return &gossh.Permissions{}, nil
				}
			}
			log.Printf("[backen-sshd] auth fail user=%s remote=%s", c.User(), c.RemoteAddr())
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("listen local ssh %s: %w", localTarget, err)
	}
	log.Printf("[backen-sshd] listening on %s", ln.Addr())

	go func() {
		<-context.Background().Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSSH(conn, cfg)
	}
}

func loadAuthorizedKeys() []gossh.PublicKey {
	var keys []gossh.PublicKey

	add := func(p string) {
		data, err := os.ReadFile(p)
		if err != nil {
			return
		}
		k, _, _, _, err := gossh.ParseAuthorizedKey(data)
		if err == nil {
			keys = append(keys, k)
		}
	}

	// 用户默认公钥
	usr, _ := user.Current()
	if usr != nil {
		home := usr.HomeDir
		add(filepathJoin(home, ".ssh", "id_ed25519.pub"))
		add(filepathJoin(home, ".ssh", "id_rsa.pub"))
	}

	// myproxy 公钥
	dir, _ := os.UserHomeDir()
	add(filepathJoin(dir, ".ssh", "myproxy", "direct.pub"))
	add(filepathJoin(dir, ".ssh", "myproxy", "proxy.pub"))

	return keys
}

func filepathJoin(parts ...string) string {
	return strings.Join(parts, string(os.PathSeparator))
}

func handleSSH(raw net.Conn, cfg *gossh.ServerConfig) {
	sshConn, chans, reqs, err := gossh.NewServerConn(raw, cfg)
	if err != nil {
		raw.Close()
		return
	}
	log.Printf("[backen-sshd] new ssh connection remote=%s", sshConn.RemoteAddr())
	go gossh.DiscardRequests(reqs)

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "session":
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}

			go func(in <-chan *gossh.Request) {
				var ptyReq bool
				for req := range in {
					switch req.Type {
					case "pty-req":
						ptyReq = true
						req.Reply(true, nil)
					case "env":
						req.Reply(true, nil)
					case "shell":
						req.Reply(true, nil)
						go launchShell(ch, ptyReq)
					case "exec":
						// Handle simple "sftp" exec for VSCode compatibility
						cmd := parseExecCmd(req.Payload)
						if cmd == "sftp" || strings.HasPrefix(cmd, "sftp ") {
							req.Reply(true, nil)
							go launchSFTP(ch)
						} else {
							req.Reply(false, nil)
						}
					case "subsystem":
						sub := parseSubsystem(req.Payload)
						if sub == "sftp" {
							req.Reply(true, nil)
							go launchSFTP(ch)
						} else {
							req.Reply(false, nil)
						}
					default:
						req.Reply(false, nil)
					}
				}
			}(reqs)
			//为了兼容vscode
		case "direct-tcpip":
			var data struct {
				Host              string
				Port              uint32
				OriginatorAddress string
				OriginatorPort    uint32
			}
			if err := gossh.Unmarshal(newCh.ExtraData(), &data); err != nil {
				newCh.Reject(gossh.UnknownChannelType, "bad direct-tcpip payload")
				continue
			}
			target := fmt.Sprintf("%s:%d", data.Host, data.Port)
			dial, err := net.Dial("tcp", target)
			if err != nil {
				newCh.Reject(gossh.ConnectionFailed, err.Error())
				continue
			}
			ch, reqs, err := newCh.Accept()
			if err != nil {
				dial.Close()
				continue
			}
			go gossh.DiscardRequests(reqs)
			log.Printf("[backen-sshd] direct-tcpip %s <- %s:%d", target, data.OriginatorAddress, data.OriginatorPort)
			go func() {
				defer ch.Close()
				defer dial.Close()
				io.Copy(ch, dial)
			}()
			go func() {
				defer ch.Close()
				defer dial.Close()
				io.Copy(dial, ch)
			}()
		default:
			newCh.Reject(gossh.UnknownChannelType, "session/direct-tcpip only")
		}
	}
}

func launchShell(ch gossh.Channel, usePty bool) {
	defer ch.Close()

	cmd := exec.Command("/bin/sh")
	var cmdStdin io.Reader = ch
	var cmdStdout io.Writer = ch
	var cmdStderr io.Writer = ch

	if usePty {
		f, err := pty.Start(cmd)
		if err != nil {
			fmt.Fprintf(ch, "failed to start pty: %v\n", err)
			return
		}
		defer f.Close()

		errCh := make(chan error, 2)
		go func() {
			_, e := io.Copy(ch, f)
			errCh <- e
		}()
		go func() {
			_, e := io.Copy(f, ch)
			errCh <- e
		}()
		<-errCh
	} else {
		cmd.Stdin = cmdStdin
		cmd.Stdout = cmdStdout
		cmd.Stderr = cmdStderr
		if err := cmd.Run(); err != nil {
			io.WriteString(ch, fmt.Sprintf("shell error: %v\n", err))
		}
	}
}

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

func launchSFTP(ch gossh.Channel) {
	server, err := sftp.NewServer(ch, sftp.WithDebug(nil))
	if err != nil {
		fmt.Fprintf(ch, "sftp start error: %v\n", err)
		ch.Close()
		return
	}
	if err := server.Serve(); err == io.EOF {
		_ = server.Close()
	} else if err != nil {
		fmt.Fprintf(ch, "sftp serve error: %v\n", err)
	}
}

func parseExecCmd(payload []byte) string {
	var msg struct {
		Command string
	}
	if err := gossh.Unmarshal(payload, &msg); err != nil {
		return ""
	}
	return msg.Command
}

func parseSubsystem(payload []byte) string {
	var msg struct {
		Subsystem string
	}
	if err := gossh.Unmarshal(payload, &msg); err != nil {
		return ""
	}
	return msg.Subsystem
}
