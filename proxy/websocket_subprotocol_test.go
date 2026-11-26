package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lqqyt2423/go-mitmproxy/cert"
)

// testTLSHandlerServer serves handler over TLS on a loopback port, with a
// certificate for localhost from a throwaway CA.
func testTLSHandlerServer(t *testing.T, handler http.Handler) *testTLSServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ca, err := cert.NewSelfSignCA("")
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	tlsCert, err := ca.GetCert("localhost")
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*tlsCert}}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig}
	tlsLn := tls.NewListener(ln, tlsConfig)
	go server.Serve(tlsLn)

	return &testTLSServer{server: server, tlsLn: tlsLn, port: ln.Addr().(*net.TCPAddr).Port}
}

// A browser sends Sec-WebSocket-Protocol to name the protocols it can speak,
// and some services also use it to carry a credential, since a browser
// WebSocket cannot set other headers. The proxy must pass the offer to the
// server and pass the server's choice back: a server that requires a protocol
// rejects the handshake without it, and a browser fails a handshake whose
// response does not confirm a protocol it offered.
func TestWebSocketWSSProxyForwardsSubprotocol(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		offered  []string
		required string // the server refuses the handshake unless this is offered
		selected []string
		want     string
	}{
		{
			name:     "the server picks one of the offered protocols",
			addr:     "127.0.0.1:29110",
			offered:  []string{"chat.v1", "chat.v2"},
			required: "chat.v2",
			selected: []string{"chat.v2"},
			want:     "chat.v2",
		},
		{
			name:     "the server picks none",
			addr:     "127.0.0.1:29111",
			offered:  []string{"chat.v1"},
			selected: nil,
			want:     "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 1)
			upgrader := websocket.Upgrader{
				Subprotocols: tc.selected,
				CheckOrigin:  func(*http.Request) bool { return true },
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("Sec-Websocket-Protocol")
				if tc.required != "" {
					offered := false
					for _, p := range websocket.Subprotocols(r) {
						offered = offered || p == tc.required
					}
					if !offered {
						http.Error(w, "subprotocol required", http.StatusUnauthorized)
						return
					}
				}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					t.Errorf("server upgrade: %v", err)
					return
				}
				testEchoWebSocketHandler(t)(conn)
			})
			server := testTLSHandlerServer(t, mux)
			defer server.Close()

			proxy, err := NewProxy(&Options{Addr: tc.addr, SslInsecure: true})
			if err != nil {
				t.Fatalf("create proxy: %v", err)
			}
			go proxy.Start()
			defer proxy.Close()
			time.Sleep(100 * time.Millisecond)

			proxyURL, _ := url.Parse("http://" + tc.addr)
			dialer := &websocket.Dialer{
				Proxy:            http.ProxyURL(proxyURL),
				TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
				HandshakeTimeout: 5 * time.Second,
				Subprotocols:     tc.offered,
			}
			conn, resp, err := dialer.Dial("wss://"+server.Addr()+"/ws", nil)
			if err != nil {
				status := "no response"
				if resp != nil {
					status = resp.Status
				}
				t.Fatalf("dial through proxy: %v (%s)", err, status)
			}
			defer conn.Close()

			if got, want := <-seen, strings.Join(tc.offered, ", "); got != want {
				t.Errorf("server received Sec-WebSocket-Protocol %q, want %q", got, want)
			}
			if got := conn.Subprotocol(); got != tc.want {
				t.Errorf("client negotiated subprotocol %q, want %q", got, tc.want)
			}

			if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, msg, err := conn.ReadMessage(); err != nil || string(msg) != "ping" {
				t.Fatalf("read: %q, %v", msg, err)
			}
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		})
	}
}
