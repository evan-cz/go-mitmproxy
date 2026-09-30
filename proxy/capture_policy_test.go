package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	log "github.com/sirupsen/logrus"
)

func TestProxyErrorLogsOmitQuery(t *testing.T) {
	const secret = "QUERY_VALUE_CANARY"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("not-an-http-response\r\n\r\n")
		_ = rw.Flush()
	}))
	defer upstream.Close()
	var output bytes.Buffer
	logger := log.StandardLogger()
	oldOutput, oldLevel := logger.Out, logger.GetLevel()
	logger.SetOutput(&output)
	logger.SetLevel(log.DebugLevel)
	defer logger.SetOutput(oldOutput)
	defer logger.SetLevel(oldLevel)

	p := &Proxy{Opts: &Options{StreamLargeBodies: 1024}}
	a := &attacker{proxy: p}
	r := httptest.NewRequest(http.MethodGet, upstream.URL+"/download?token="+secret, nil)
	connCtx := &ConnContext{ServerConn: &ServerConn{client: upstream.Client()}}
	r = r.WithContext(context.WithValue(r.Context(), connContextKey, connCtx))
	w := httptest.NewRecorder()
	a.attack(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if got := output.String(); strings.Contains(got, secret) || !strings.Contains(got, "malformed HTTP response") || !strings.Contains(got, "/download") {
		t.Fatalf("unsafe or missing diagnostic: %s", got)
	}
	if r.URL.RawQuery != "token="+secret {
		t.Fatal("logging changed the request URL")
	}
}

func TestLogErrPreservesClassificationWithoutURL(t *testing.T) {
	for _, tc := range []struct {
		message string
		logged  bool
	}{
		{"connect: connection refused", false},
		{"malformed HTTP response", true},
	} {
		t.Run(tc.message, func(t *testing.T) {
			var output bytes.Buffer
			logger := log.New()
			logger.SetOutput(&output)
			logger.SetLevel(log.DebugLevel)
			err := fmt.Errorf("request: %w", &url.Error{Op: "Get", URL: "https://example.com/file?secret=CANARY", Err: errors.New(tc.message)})
			if got := logErr(log.NewEntry(logger), err); got != tc.logged {
				t.Fatalf("logged = %v, want %v", got, tc.logged)
			}
			if got := output.String(); strings.Contains(got, "CANARY") || !strings.Contains(got, tc.message) {
				t.Fatalf("unsafe or missing cause: %s", got)
			}
		})
	}
}

type capturePolicyAddon struct {
	BaseAddon
	skip               bool
	observed, modified atomic.Int32
	ended              chan *Flow
}

func (a *capturePolicyAddon) WebSocketStart(f *Flow) { f.SkipWebSocketCapture = a.skip }
func (a *capturePolicyAddon) WebSocketMessage(*Flow) { a.observed.Add(1) }
func (a *capturePolicyAddon) RewriteWebSocketMessage(_ *Flow, m *WebSocketMessage) {
	a.modified.Add(1)
	m.Content = []byte("rewritten")
}
func (a *capturePolicyAddon) WebSocketEnd(f *Flow) {
	if a.ended != nil {
		a.ended <- f
	}
}

func TestWebSocketCapturePolicyThroughTLSProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "key=preserved" {
			t.Error("WebSocket query changed")
		}
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		kind, body, err := conn.ReadMessage()
		if err == nil {
			_ = conn.WriteMessage(kind, body)
		}
		_, _, _ = conn.ReadMessage()
	}))
	defer upstream.Close()
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprint(skip), func(t *testing.T) {
			a := &capturePolicyAddon{skip: skip, ended: make(chan *Flow, 1)}
			p, err := NewProxy(&Options{NewCaFunc: cert.NewSelfSignCAMemory, SslInsecure: true})
			handleError(t, err)
			p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) { return nil, nil })
			p.AddAddon(a)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			handleError(t, err)
			go p.attacker.start()
			go p.entry.server.Serve(&wrapListener{Listener: ln, proxy: p})
			defer p.Close()
			dialer := &websocket.Dialer{
				Proxy:            http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
				TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
				HandshakeTimeout: 5 * time.Second,
			}
			conn, _, err := dialer.Dial("wss"+strings.TrimPrefix(upstream.URL, "https")+"/ws?key=preserved", nil)
			handleError(t, err)
			defer conn.Close()
			input := []byte{0, 1, 255, 42}
			handleError(t, conn.WriteMessage(websocket.BinaryMessage, input))
			handleError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			kind, got, err := conn.ReadMessage()
			handleError(t, err)
			want := []byte("rewritten")
			if skip {
				want = input
			}
			if kind != websocket.BinaryMessage || !bytes.Equal(got, want) {
				t.Fatalf("forwarded kind/body = %d/%v, want binary/%v", kind, got, want)
			}
			_ = conn.Close()
			select {
			case f := <-a.ended:
				count := 2
				if skip {
					count = 0
				}
				if f.WebScoket.Len() != count || int(a.observed.Load()) != count || int(a.modified.Load()) != count {
					t.Fatalf("capture remained active: history=%d observed=%d modified=%d", f.WebScoket.Len(), a.observed.Load(), a.modified.Load())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("WebSocketEnd not called")
			}
		})
	}
}
