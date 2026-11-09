package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	uuid "github.com/google/uuid"
)

// client connection
type ClientConn struct {
	Id                 uuid.UUID
	Conn               net.Conn
	Tls                bool
	NegotiatedProtocol string
	UpstreamCert       bool // Connect to upstream server to look up certificate details. Default: True
	clientHello        *tls.ClientHelloInfo
}

func newClientConn(c net.Conn) *ClientConn {
	return &ClientConn{
		Id:           uuid.New(),
		Conn:         c,
		Tls:          false,
		UpstreamCert: true,
	}
}

func (c *ClientConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["id"] = c.Id
	m["tls"] = c.Tls
	m["address"] = c.Conn.RemoteAddr().String()
	return json.Marshal(m)
}

// server connection
type ServerConn struct {
	Id      uuid.UUID
	Address string
	Conn    net.Conn

	client   *http.Client
	tlsConn  *tls.Conn
	tlsState *tls.ConnectionState
}

func newServerConn() *ServerConn {
	return &ServerConn{
		Id: uuid.New(),
	}
}

func (c *ServerConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["id"] = c.Id
	m["address"] = c.Address
	peername := ""
	if c.Conn != nil {
		peername = c.Conn.RemoteAddr().String()
	}
	m["peername"] = peername
	return json.Marshal(m)
}

func (c *ServerConn) TlsState() *tls.ConnectionState {
	return c.tlsState
}

// connection context ctx key
var connContextKey = new(struct{})

// connection context
type ConnContext struct {
	ClientConn *ClientConn   `json:"clientConn"`
	ServerConn *ServerConn   `json:"serverConn"`
	Intercept  bool          `json:"intercept"` // Indicates whether to parse HTTPS
	FlowCount  atomic.Uint32 `json:"-"`         // Number of HTTP requests made on the same connection

	proxy              *Proxy
	closeAfterResponse bool                        // after http response, http server will close the connection
	dialFn             func(context.Context) error // when begin request, if there no ServerConn, use this func to dial

	// clientMu guards clientActive, h2Handlers and closeClientWhenIdle. An
	// HTTP/1 client connection is active from when the attacker server starts
	// reading a request on it until that request's response has been written;
	// an HTTP/2 one while any of its streams' handlers is running.
	clientMu            sync.Mutex
	clientActive        bool
	h2Handlers          int
	closeClientWhenIdle bool
}

// deferredClientCloseLimit bounds how long a deferred client close waits for
// the response in progress, so a client that stalls mid-request cannot hold
// the connection open indefinitely.
const deferredClientCloseLimit = time.Minute

// h2FlushGrace is how long a deferred close of an HTTP/2 client connection
// waits after its last handler returns: the HTTP/2 server writes a stream's
// final frames after the handler returns, and has no hook for when it has.
const h2FlushGrace = 500 * time.Millisecond

// closeClientOrDefer closes the client connection, or, if a response is still
// being written to it, closes it once that response is done. The server
// connection can close first: when an upstream answers before it has read the
// whole request body, the transport closes it as soon as the answer is read.
func (connCtx *ConnContext) closeClientOrDefer() {
	connCtx.clientMu.Lock()
	if connCtx.clientActive || connCtx.h2Handlers > 0 {
		connCtx.closeClientWhenIdle = true
		connCtx.clientMu.Unlock()
		time.AfterFunc(deferredClientCloseLimit, func() {
			connCtx.clientMu.Lock()
			pending := connCtx.closeClientWhenIdle
			connCtx.closeClientWhenIdle = false
			connCtx.clientMu.Unlock()
			if pending {
				connCtx.ClientConn.Conn.Close()
			}
		})
		return
	}
	connCtx.clientMu.Unlock()
	connCtx.ClientConn.Conn.Close()
}

// h2HandlerStarted and h2HandlerDone bracket a handler serving one stream of
// an HTTP/2 client connection. When the last handler returns and a close was
// deferred, the connection is closed once its final frames have gone out.
func (connCtx *ConnContext) h2HandlerStarted() {
	connCtx.clientMu.Lock()
	connCtx.h2Handlers++
	connCtx.clientMu.Unlock()
}

func (connCtx *ConnContext) h2HandlerDone() {
	connCtx.clientMu.Lock()
	connCtx.h2Handlers--
	closeNow := connCtx.h2Handlers == 0 && connCtx.closeClientWhenIdle
	if closeNow {
		connCtx.closeClientWhenIdle = false
	}
	connCtx.clientMu.Unlock()
	if closeNow {
		time.AfterFunc(h2FlushGrace, func() { connCtx.ClientConn.Conn.Close() })
	}
}

// clientStateChanged tracks the HTTP/1 attacker server's state for the client
// connection, and makes a close that closeClientOrDefer deferred once the
// response has been written.
func (connCtx *ConnContext) clientStateChanged(state http.ConnState) {
	connCtx.clientMu.Lock()
	closeNow := false
	switch state {
	case http.StateActive:
		connCtx.clientActive = true
	case http.StateIdle:
		connCtx.clientActive = false
		closeNow = connCtx.closeClientWhenIdle
		connCtx.closeClientWhenIdle = false
	case http.StateHijacked, http.StateClosed:
		connCtx.clientActive = false
		connCtx.closeClientWhenIdle = false
	}
	connCtx.clientMu.Unlock()
	if closeNow {
		connCtx.ClientConn.Conn.Close()
	}
}

func newConnContext(c net.Conn, proxy *Proxy) *ConnContext {
	clientConn := newClientConn(c)
	return &ConnContext{
		ClientConn: clientConn,
		proxy:      proxy,
	}
}

func (connCtx *ConnContext) Id() uuid.UUID {
	return connCtx.ClientConn.Id
}
