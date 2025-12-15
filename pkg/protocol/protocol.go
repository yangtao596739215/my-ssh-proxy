package protocol

// Protocol constants and payloads shared between server and backend client.
// They intentionally mirror the OpenSSH streamlocal forwarding naming so that
// standard SSH clients can interact with the server without custom extensions.

const (
	// ForwardRequestType is the global request used by backend agents to ask
	// the relay server to expose a Unix domain socket.
	ForwardRequestType = "streamlocal-forward@openssh.com"
	// ForwardedRequestType is the channel type the server opens back toward
	// the backend agent whenever a direct client connects to the exposed socket.
	ForwardedRequestType = "forwarded-streamlocal@openssh.com"

	// UpdateAuthKeyRequestType lets a client push a public key for the given
	// SSH username so the server can accept it without restarting.
	UpdateAuthKeyRequestType = "update-authorized-key"
)

// RemoteForwardRequest describes the Unix socket the backend wants to expose.
// When BindUnixSocket is relative, the server will join it with its socket
// directory; absolute paths are also permitted.
type RemoteForwardRequest struct {
	BindUnixSocket string
}

// UpdateAuthKeyRequest is a simple payload to append a new authorized key
// for the specified SSH username.
type UpdateAuthKeyRequest struct {
	User          string
	AuthorizedKey string
}

