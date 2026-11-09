package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
)

// An upstream may answer a request before it has read the whole body, for
// example rejecting a bad credential after the headers and the first part of
// a large body. The proxy must hand that answer to the client rather than
// close the client connection when the upstream connection goes away.

const earlyAnswerBody = `{"error":"invalid credentials"}`

// earlyAnswerUpstream reads the first 100 KiB of each request body, then
// answers 401 and stops reading.
//   - keepAlive: the answer says "Connection: keep-alive" and the connection
//     stays open with the rest of the body unread, as some API servers answer
//     a rejected credential. HTTP/1.1 only.
//   - otherwise the answer says "Connection: close"; over HTTP/2 the upstream
//     then sends GOAWAY and closes the connection right after answering.
func earlyAnswerUpstream(t *testing.T, enableHTTP2, keepAlive bool) *httptest.Server {
	t.Helper()
	done := make(chan struct{})
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.CopyN(io.Discard, r.Body, 100<<10)
		if keepAlive {
			// net/http would add "Connection: close" itself for a body left
			// unread, so write the answer on the raw connection instead.
			conn, buf, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			_, _ = fmt.Fprintf(buf, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(earlyAnswerBody), earlyAnswerBody)
			_ = buf.Flush()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(earlyAnswerBody))
	}))
	upstream.EnableHTTP2 = enableHTTP2
	upstream.StartTLS()
	t.Cleanup(func() { close(done); upstream.Close() })
	return upstream
}

// startEarlyAnswerProxy starts a proxy that buffers whole request and response
// bodies, and returns its URL.
func startEarlyAnswerProxy(t *testing.T) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	handleError(t, err)
	addr := ln.Addr().String()
	_ = ln.Close()

	p, err := NewProxy(&Options{
		Addr:              addr,
		StreamLargeBodies: 0x7FFFFFFFFFFFFFFE,
		SslInsecure:       true,
		NewCaFunc:         cert.NewSelfSignCAMemory,
	})
	handleError(t, err)
	go func() { _ = p.Start() }()
	t.Cleanup(func() { _ = p.Close() })

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start listening on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &url.URL{Scheme: "http", Host: addr}
}

func earlyAnswerClient(t *testing.T, proxyURL *url.URL, http2 bool) *http.Client {
	t.Helper()
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: http2,
	}
	if !http2 {
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// postLargeAndRequireAnswer posts 32 MiB, large enough that the proxy's upload
// upstream is still running when the answer arrives (loopback socket buffers
// absorb a few MiB), and requires the upstream's 401 to reach the client. With
// allowBadGateway, the proxy's own 502 is accepted in its place (see the HTTP/2
// test); a missing response never is.
func postLargeAndRequireAnswer(t *testing.T, client *http.Client, target string, allowBadGateway bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("a"), 32<<20)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	handleError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client got %v; want the upstream's 401", err)
	}
	defer resp.Body.Close()
	// Read the whole body first: a response that starts and then resets is not
	// a complete response, whatever its status.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("response %d ended with %v; want a complete response", resp.StatusCode, err)
	}
	if allowBadGateway && resp.StatusCode == http.StatusBadGateway {
		t.Logf("transport reported the upstream close first; the proxy answered 502")
		return
	}
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "invalid credentials") {
		t.Fatalf("got %d %q; want the upstream's 401", resp.StatusCode, body)
	}
}

func TestAttackerDeliversEarlyKeepAliveAnswerToHTTP1Client(t *testing.T) {
	upstream := earlyAnswerUpstream(t, false, true)
	client := earlyAnswerClient(t, startEarlyAnswerProxy(t), false)
	postLargeAndRequireAnswer(t, client, upstream.URL+"/upload", false)
}

// The upstream sends GOAWAY and closes right after its early answer. The client
// must get a complete response: the upstream's 401, or the proxy's 502 when
// x/net/http2's RoundTrip sees the closed connection first. Both can be ready
// at once, and RoundTrip then picks one at random.
func TestAttackerAnswersHTTP2ClientWhenUpstreamClosesAfterAnswering(t *testing.T) {
	upstream := earlyAnswerUpstream(t, true, false)
	client := earlyAnswerClient(t, startEarlyAnswerProxy(t), true)
	postLargeAndRequireAnswer(t, client, upstream.URL+"/upload", true)
}
