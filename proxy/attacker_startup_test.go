package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	"golang.org/x/net/http2"
)

func TestAttackerHTTP1AndHTTP2StartConcurrently(t *testing.T) {
	for i := 0; i < 20; i++ {
		proxy, serverTLS, client := newAttackerHTTP2TestClient(t)
		listener := newBlockingListener()
		serveDone := make(chan error, 1)
		start := make(chan struct{})

		go func() {
			<-start
			serveDone <- proxy.attacker.server.Serve(listener)
		}()
		go func() {
			<-start
			proxy.attacker.serveConn(serverTLS.Conn, serverTLS.connCtx)
		}()

		close(start)
		assertAttackerHTTP2Response(t, client)
		listener.Close()
		if err := <-serveDone; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("HTTP/1 server returned %v", err)
		}
	}
}

func TestAttackerHTTP2UsesProxyHandler(t *testing.T) {
	_, serverTLS, client := newAttackerHTTP2TestClient(t)
	serverTLS.attacker.serveConn(serverTLS.Conn, serverTLS.connCtx)

	assertAttackerHTTP2Response(t, client)
}

func TestAttackerHTTP2PreservesConnectionContext(t *testing.T) {
	proxy, serverTLS, client := newAttackerHTTP2TestClient(t)
	serverTLS.attacker.serveConn(serverTLS.Conn, serverTLS.connCtx)

	assertAttackerHTTP2Response(t, client)
	got := waitAttackerHTTP2TestRequest(t, proxy)
	if got.connCtx != serverTLS.connCtx {
		t.Fatal("HTTP/2 request did not preserve its connection context")
	}
}

func TestAttackerHTTP2UsesIndependentBaseConfig(t *testing.T) {
	proxy, serverTLS, client := newAttackerHTTP2TestClient(t)
	serverTLS.attacker.serveConn(serverTLS.Conn, serverTLS.connCtx)

	assertAttackerHTTP2Response(t, client)
	got := waitAttackerHTTP2TestRequest(t, proxy)
	if got.server == proxy.attacker.server {
		t.Fatal("HTTP/2 request reused the mutable HTTP/1 server")
	}
	if got.server == nil || got.server.Handler != proxy.attacker || got.server.ConnContext == nil {
		t.Fatal("HTTP/2 request did not receive the proxy server configuration")
	}
}

func waitAttackerHTTP2TestRequest(t *testing.T, proxy *Proxy) http2TestRequest {
	t.Helper()

	select {
	case got := <-proxy.Addons[0].(*http2TestAddon).requests:
		return got
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP/2 request context")
	}
	return http2TestRequest{}
}

type attackerHTTP2TestConn struct {
	*tls.Conn
	attacker *attacker
	connCtx  *ConnContext
}

func newAttackerHTTP2TestClient(t *testing.T) (*Proxy, *attackerHTTP2TestConn, *http.Client) {
	t.Helper()

	proxy, err := NewProxy(&Options{NewCaFunc: cert.NewSelfSignCAMemory})
	if err != nil {
		t.Fatal(err)
	}
	proxy.AddAddon(&http2TestAddon{requests: make(chan http2TestRequest, 1)})

	clientConn, serverConn := net.Pipe()
	wrapped := newWrapClientConn(serverConn, proxy)
	connCtx := newConnContext(wrapped, proxy)
	wrapped.connCtx = connCtx
	connCtx.ServerConn = newServerConn()

	certificate, err := proxy.attacker.ca.GetCert("example.test")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := tls.Server(wrapped, &tls.Config{
		Certificates: []tls.Certificate{*certificate},
		NextProtos:   []string{"h2"},
	})
	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})

	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatal(err)
	}

	transport := &http2.Transport{
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return clientTLS, nil
		},
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = clientTLS.Close()
		_ = wrapped.Close()
	})

	return proxy, &attackerHTTP2TestConn{Conn: serverTLS, attacker: proxy.attacker, connCtx: connCtx}, &http.Client{Transport: transport}
}

func assertAttackerHTTP2Response(t *testing.T, client *http.Client) {
	t.Helper()

	request, err := http.NewRequest(http.MethodGet, "https://example.test/handled", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "handled by attacker" {
		t.Fatalf("response body = %q, want %q", body, "handled by attacker")
	}
}

type http2TestRequest struct {
	connCtx *ConnContext
	server  *http.Server
}

type http2TestAddon struct {
	BaseAddon
	requests chan http2TestRequest
}

func (a *http2TestAddon) Requestheaders(flow *Flow) {
	server, _ := flow.Request.Raw().Context().Value(http.ServerContextKey).(*http.Server)
	a.requests <- http2TestRequest{connCtx: flow.ConnContext, server: server}
	flow.Response = &Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       []byte("handled by attacker"),
	}
}

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingListener() *blockingListener {
	return &blockingListener{closed: make(chan struct{})}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingListener) Addr() net.Addr { return testAddr("http1") }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }
