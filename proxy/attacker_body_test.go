package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestAttackerHTTP2EmptyRequestEndsAtHeaders(t *testing.T) {
	for _, tc := range []struct {
		name, method     string
		stream, separate bool
	}{
		{"streamed_get", "GET", true, false},
		{"streamed_head", "HEAD", true, false},
		{"streamed_post", "POST", true, false},
		{"buffered_get", "GET", false, false},
		{"separate_client", "GET", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testAttackerBodyForwarding(t, tc.method, nil, &requestBodyAddon{stream: tc.stream, separate: tc.separate}, "", 0)
		})
	}
}

func TestAttackerHTTP2PreservesRequestBodies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   io.Reader
		addon  requestBodyAddon
		want   string
		length int64
	}{
		{"known_length", strings.NewReader("payload"), requestBodyAddon{stream: true}, "payload", 7},
		{"unknown_length", io.NopCloser(strings.NewReader("payload")), requestBodyAddon{stream: true}, "payload", -1},
		{"buffered_body", strings.NewReader("payload"), requestBodyAddon{}, "payload", 7},
		{"stream_modifier", nil, requestBodyAddon{stream: true, modified: "injected"}, "injected", 0},
		{"buffered_request_hook", nil, requestBodyAddon{buffered: "injected"}, "injected", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testAttackerBodyForwarding(t, "POST", tc.body, &tc.addon, tc.want, tc.length)
		})
	}
}

type requestBodyAddon struct {
	BaseAddon
	stream, separate   bool
	modified, buffered string
}

func (a *requestBodyAddon) Requestheaders(f *Flow) {
	f.Stream = a.stream
	f.UseSeparateClient = a.separate
}

func (a *requestBodyAddon) Request(f *Flow) {
	if a.buffered != "" {
		f.Request.Body = []byte(a.buffered)
	}
}

func (a *requestBodyAddon) StreamRequestModifier(_ *Flow, body io.Reader) io.Reader {
	if a.modified != "" {
		return strings.NewReader(a.modified)
	}
	return body
}

type requestWireConn struct {
	net.Conn
	mu   sync.Mutex
	wire bytes.Buffer
}

func (c *requestWireConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.wire.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func bodyTestHTTP2Client(t *testing.T, handler http.Handler) (*http.Client, *requestWireConn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	capture := &requestWireConn{Conn: clientConn}
	transport := &http2.Transport{
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return capture, nil
		},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&http2.Server{}).ServeConn(serverConn, &http2.ServeConnOpts{Handler: handler})
	}()
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		clientConn.Close()
		serverConn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("HTTP/2 server did not stop")
		}
	})
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, capture
}

func testAttackerBodyForwarding(t *testing.T, method string, body io.Reader, addon *requestBodyAddon, want string, length int64) {
	t.Helper()
	upstreamBody := make(chan string, 1)
	upstream, capture := bodyTestHTTP2Client(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		upstreamBody <- string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	a := &attacker{proxy: &Proxy{Opts: &Options{StreamLargeBodies: 1024}, Addons: []Addon{addon}}, client: upstream}
	connCtx := &ConnContext{ServerConn: &ServerConn{client: upstream}}
	type incomingBody struct {
		length     int64
		serverBody bool
	}
	incoming := make(chan incomingBody, 1)
	downstream, _ := bodyTestHTTP2Client(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		incoming <- incomingBody{r.ContentLength, r.Body != nil && r.Body != http.NoBody}
		a.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), connContextKey, connCtx)))
	}))
	req, err := http.NewRequest(method, "https://example.test/bootstrap", body)
	if err != nil {
		t.Fatal(err)
	}
	res, err := downstream.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", res.StatusCode)
	}
	gotIncoming := <-incoming
	if gotIncoming.length != length || !gotIncoming.serverBody {
		t.Fatalf("incoming body = %+v, want non-sentinel server body with length %d", gotIncoming, length)
	}
	if got := <-upstreamBody; got != want {
		t.Errorf("upstream body = %q, want %q", got, want)
	}
	capture.mu.Lock()
	wire := bytes.Clone(capture.wire.Bytes())
	capture.mu.Unlock()
	if !bytes.HasPrefix(wire, []byte(http2.ClientPreface)) {
		t.Fatal("missing upstream HTTP/2 preface")
	}
	fr := http2.NewFramer(nil, bytes.NewReader(wire[len(http2.ClientPreface):]))
	var headersSeen, headersEnd bool
	dataFrames := 0
	for {
		frame, err := fr.ReadFrame()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch frame := frame.(type) {
		case *http2.HeadersFrame:
			headersSeen, headersEnd = true, frame.StreamEnded()
		case *http2.DataFrame:
			dataFrames++
		}
	}
	if !headersSeen {
		t.Fatal("missing upstream request HEADERS")
	}
	if want == "" && (!headersEnd || dataFrames != 0) {
		t.Errorf("empty upstream request: HEADERS END_STREAM=%v, DATA frames=%d; want true, 0", headersEnd, dataFrames)
	}
}
