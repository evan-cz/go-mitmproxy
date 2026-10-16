package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
)

type ssePolicyAddon struct {
	BaseAddon
	skip                   bool
	requestHook            bool
	flow                   chan *Flow
	starts, messages, ends int
	parsed                 bool
	readErr                error
}

func (a *ssePolicyAddon) Requestheaders(f *Flow) {
	if a.requestHook {
		f.SkipSSEParsing = a.skip
	}
}
func (a *ssePolicyAddon) Responseheaders(f *Flow) {
	if !a.requestHook {
		f.SkipSSEParsing = a.skip
	}
	a.flow <- f
}
func (a *ssePolicyAddon) SSEStart(*Flow)   { a.starts++ }
func (a *ssePolicyAddon) SSEMessage(*Flow) { a.messages++ }
func (a *ssePolicyAddon) SSEEnd(*Flow)     { a.ends++ }
func (a *ssePolicyAddon) StreamResponseModifier(_ *Flow, r io.Reader) io.Reader {
	_, a.parsed = r.(*sseReader)
	if r == nil {
		return nil
	}
	return &ssePolicyReader{r: r, addon: a}
}

type ssePolicyReader struct {
	r     io.Reader
	addon *ssePolicyAddon
}

func (r *ssePolicyReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil {
		r.addon.readErr = err
	}
	return n, err
}

func ssePolicyClient(t *testing.T, a *ssePolicyAddon) *http.Client {
	t.Helper()
	p, err := NewProxy(&Options{NewCaFunc: cert.NewSelfSignCAMemory})
	handleError(t, err)
	p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) { return nil, nil })
	p.AddAddon(a)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	handleError(t, err)
	stopped := make(chan error, 1)
	go func() { stopped <- p.entry.server.Serve(&wrapListener{Listener: ln, proxy: p}) }()
	proxyURL := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = p.Close()
		select {
		case err := <-stopped:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("proxy did not stop")
		}
	})
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}
func waitSSEPolicyFlow(t *testing.T, a *ssePolicyAddon) *Flow {
	t.Helper()
	select {
	case f := <-a.flow:
		select {
		case <-f.Done():
			return f
		case <-time.After(time.Second):
			t.Fatal("flow did not finish")
		}
	case <-time.After(time.Second):
		t.Fatal("response headers not observed")
	}
	return nil
}

func TestSSEParsingPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		skip, requestHook, binary bool
	}{
		{name: "default"}, {name: "opt out", skip: true},
		{name: "binary response hook", skip: true, binary: true},
		{name: "binary request hook", skip: true, requestHook: true, binary: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := []byte("data: first\n\n")
			last := []byte("data: second\n\n")
			if tc.binary {
				first = bytes.Repeat([]byte{0, 0, 0, 0, 3, 255, 128, 1}, 8192)
				last = []byte{2, 0, 0, 0, 2, '{', '}'}
			}
			release := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Test-Request") != "preserve" {
					t.Error("request header changed")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("X-Test-Response", "preserve")
				for offset := 0; offset < len(first); {
					end := min(offset+7, len(first))
					_, _ = w.Write(first[offset:end])
					w.(http.Flusher).Flush()
					offset = end
				}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				_, _ = w.Write(last)
			}))
			defer upstream.Close()
			defer close(release)
			a := &ssePolicyAddon{skip: tc.skip, requestHook: tc.requestHook, flow: make(chan *Flow, 1)}
			client := ssePolicyClient(t, a)
			request, _ := http.NewRequest("GET", upstream.URL, nil)
			request.Header.Set("X-Test-Request", "preserve")
			response, err := client.Do(request)
			handleError(t, err)
			defer response.Body.Close()
			if response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("X-Test-Response") != "preserve" {
				t.Fatal("response headers changed")
			}
			got := make([]byte, len(first))
			_, err = io.ReadFull(response.Body, got)
			handleError(t, err)
			if !bytes.Equal(got, first) {
				t.Fatal("first bytes changed")
			}
			release <- struct{}{}
			tail, err := io.ReadAll(response.Body)
			handleError(t, err)
			if !bytes.Equal(tail, last) {
				t.Fatal("tail bytes changed")
			}
			f := waitSSEPolicyFlow(t, a)
			if !f.Stream || a.parsed == tc.skip {
				t.Fatal("wrong streaming/parser selection")
			}
			if tc.skip {
				if f.SSE != nil || a.starts != 0 || a.messages != 0 || a.ends != 0 {
					t.Fatal("opt-out allocated SSE data or called SSE hooks")
				}
			} else if f.SSE == nil || len(f.SSE.Events) != 2 || a.starts != 1 || a.messages != 2 || a.ends != 1 {
				t.Fatal("default SSE behavior changed")
			}
			if a.readErr != io.EOF {
				t.Fatalf("terminal error: %v", a.readErr)
			}
		})
	}
}

func TestSSEParsingPolicyReadFailure(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprint(skip), func(t *testing.T) {
			body := []byte("data: partial\n\n")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = fmt.Fprint(rw, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\n\r\n")
				_, _ = rw.Write(body)
				_ = rw.Flush()
			}))
			defer upstream.Close()
			a := &ssePolicyAddon{skip: skip, flow: make(chan *Flow, 1)}
			response, err := ssePolicyClient(t, a).Get(upstream.URL)
			handleError(t, err)
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if !bytes.Equal(got, body) || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("forwarded bytes/error: %q %v", got, err)
			}
			f := waitSSEPolicyFlow(t, a)
			if !errors.Is(a.readErr, io.ErrUnexpectedEOF) {
				t.Fatalf("reader error changed: %v", a.readErr)
			}
			if skip && (f.SSE != nil || a.parsed || a.starts != 0 || a.ends != 0) {
				t.Fatal("parser active after opt-out")
			}
		})
	}
}

func TestSSEParsingPolicyNonSSERemainsBuffered(t *testing.T) {
	body := []byte("ordinary response")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	a := &ssePolicyAddon{skip: true, flow: make(chan *Flow, 1)}
	response, err := ssePolicyClient(t, a).Get(upstream.URL)
	handleError(t, err)
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	handleError(t, err)
	f := waitSSEPolicyFlow(t, a)
	if !bytes.Equal(got, body) || !bytes.Equal(f.Response.Body, body) || f.Stream || f.SSE != nil || a.parsed {
		t.Fatal("SSE opt-out changed a non-SSE response")
	}
}
