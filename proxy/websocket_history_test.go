package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// historyAddon checks, for every message, what f.WebSocket holds while the
// message's hooks run, and records what it holds when the connection ends.
type historyAddon struct {
	BaseAddon
	limit int // most entries Messages may hold; 0 for no limit

	mu       sync.Mutex
	problems []string
	seen     map[string]int // "C:payload" / "S:payload" -> times observed as the last entry
	ended    chan struct{}
	endLen   int
	endCount int
	endLast  *WebSocketMessage
}

func newHistoryAddon(limit int) *historyAddon {
	return &historyAddon{limit: limit, seen: make(map[string]int), ended: make(chan struct{})}
}

func (a *historyAddon) problem(format string, args ...interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.problems) < 10 {
		a.problems = append(a.problems, fmt.Sprintf(format, args...))
	}
}

func (a *historyAddon) checkLen(f *Flow, hook string) {
	if n := len(f.WebSocket.Messages); a.limit > 0 && n > a.limit {
		a.problem("%s: f.WebSocket.Messages has %d entries, limit %d", hook, n, a.limit)
	}
}

func (a *historyAddon) WebSocketMessage(f *Flow) {
	a.checkLen(f, "WebSocketMessage")
	if len(f.WebSocket.Messages) == 0 {
		a.problem("WebSocketMessage: f.WebSocket.Messages is empty")
		return
	}
	last := f.WebSocket.Messages[len(f.WebSocket.Messages)-1]
	dir := "S:"
	if last.FromClient {
		dir = "C:"
	}
	a.mu.Lock()
	a.seen[dir+string(last.Content)]++
	a.mu.Unlock()
}

// RewriteWebSocketMessage checks that the message being modified, the one the
// relay is about to forward, is the last entry in f.WebSocket.Messages.
func (a *historyAddon) RewriteWebSocketMessage(f *Flow, m *WebSocketMessage) {
	a.checkLen(f, "RewriteWebSocketMessage")
	if n := len(f.WebSocket.Messages); n == 0 || f.WebSocket.Messages[n-1] != m {
		a.problem("RewriteWebSocketMessage: the current message %q is not the last entry", m.Content)
	}
}

func (a *historyAddon) WebSocketEnd(f *Flow) {
	a.checkLen(f, "WebSocketEnd")
	a.mu.Lock()
	a.endLen = len(f.WebSocket.Messages)
	a.endCount = f.WebSocket.MessageCount
	if a.endLen > 0 {
		a.endLast = f.WebSocket.Messages[a.endLen-1]
	}
	a.mu.Unlock()
	close(a.ended)
}

// recordingEchoHandler echoes every message back and records, in order, the
// payloads the server received.
func recordingEchoHandler(received *[]string, mu *sync.Mutex) func(*websocket.Conn) {
	return func(conn *websocket.Conn) {
		defer conn.Close()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			mu.Lock()
			*received = append(*received, string(msg))
			mu.Unlock()
			if err := conn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}
}

type historyCase struct {
	name    string
	addr    string
	tls     bool
	discard bool // Options.DiscardWebSocketHistory
}

// runHistoryCase sends n numbered messages through the proxy to an echo
// server, so n messages travel each way, and checks that every message reached
// each peer unchanged and in order, and that each message's hooks saw it as the
// last entry in f.WebSocket.Messages. With DiscardWebSocketHistory the hooks
// must see at most one entry. It returns the addon once WebSocketEnd has run.
func runHistoryCase(t *testing.T, c historyCase, n int) *historyAddon {
	t.Helper()
	var received []string
	var receivedMu sync.Mutex
	handler := recordingEchoHandler(&received, &receivedMu)

	var endpoint string
	if c.tls {
		srv := testTLSWebSocketServer(t, handler)
		t.Cleanup(srv.Close)
		endpoint = "wss://" + srv.Addr() + "/ws"
	} else {
		srv := testWebSocketServer(t, handler)
		t.Cleanup(srv.Close)
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		endpoint = "ws://" + u.Host + "/ws"
	}

	proxy, err := NewProxy(&Options{Addr: c.addr, SslInsecure: true, DiscardWebSocketHistory: c.discard})
	if err != nil {
		t.Fatal(err)
	}
	limit := 1
	if !c.discard {
		limit = 0
	}
	addon := newHistoryAddon(limit)
	proxy.AddAddon(addon)
	go proxy.Start()
	t.Cleanup(func() { proxy.Close() })
	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://127.0.0.1" + c.addr)
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		HandshakeTimeout: 5 * time.Second,
	}
	conn, resp, err := dialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatalf("dial via proxy: %v, response: %v", err, resp)
	}
	defer conn.Close()

	echoed := make(chan []string, 1)
	go func() {
		var got []string
		for i := 0; i < n; i++ {
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			got = append(got, string(msg))
		}
		echoed <- got
	}()
	for i := 0; i < n; i++ {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("m-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	got := <-echoed

	want := make([]string, n)
	for i := range want {
		want[i] = fmt.Sprintf("m-%d", i)
	}
	receivedMu.Lock()
	serverGot := append([]string(nil), received...)
	receivedMu.Unlock()
	for _, side := range []struct {
		name string
		got  []string
	}{{"server", serverGot}, {"client", got}} {
		if len(side.got) != n {
			t.Fatalf("%s received %d messages, want %d", side.name, len(side.got), n)
		}
		for i := range want {
			if side.got[i] != want[i] {
				t.Fatalf("%s message %d: got %q, want %q", side.name, i, side.got[i], want[i])
			}
		}
	}

	if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-addon.ended:
	case <-time.After(10 * time.Second):
		t.Fatal("WebSocketEnd did not run")
	}

	addon.mu.Lock()
	defer addon.mu.Unlock()
	for _, p := range addon.problems {
		t.Error(p)
	}
	for _, dir := range []string{"C:", "S:"} {
		for _, w := range want {
			if k := addon.seen[dir+w]; k != 1 {
				t.Errorf("WebSocketMessage saw %s%s as the last entry %d times, want 1", dir, w, k)
			}
		}
	}
	if len(addon.seen) != 2*n {
		t.Errorf("WebSocketMessage saw %d distinct last entries, want %d", len(addon.seen), 2*n)
	}
	if addon.endCount != 2*n {
		t.Errorf("WebSocketEnd saw MessageCount %d, want %d", addon.endCount, 2*n)
	}
	// The last frame recorded is the server's echo of the last client
	// message: it can only be sent after that message was recorded.
	if addon.endLast == nil || addon.endLast.FromClient || string(addon.endLast.Content) != want[n-1] {
		t.Errorf("WebSocketEnd's last entry is %+v, want the server's echo of %s", addon.endLast, want[n-1])
	}
	return addon
}

// TestWebSocketDefaultKeepsEveryMessage preserves existing callers' history
// on both the plain (ws) and TLS (wss) relay paths.
func TestWebSocketDefaultKeepsEveryMessage(t *testing.T) {
	log.SetLevel(log.ErrorLevel)
	const n = 300
	for _, c := range []historyCase{
		{name: "ws", addr: ":29120"},
		{name: "wss", addr: ":29121", tls: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := runHistoryCase(t, c, n)
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.endLen != 2*n {
				t.Errorf("WebSocketEnd saw %d messages, want every one of %d", a.endLen, 2*n)
			}
		})
	}
}

// TestWebSocketDiscardHistoryKeepsOnlyCurrentMessage checks opt-in retention.
func TestWebSocketDiscardHistoryKeepsOnlyCurrentMessage(t *testing.T) {
	log.SetLevel(log.ErrorLevel)
	const n = 300
	for _, c := range []historyCase{
		{name: "ws", addr: ":29122", discard: true},
		{name: "wss", addr: ":29123", tls: true, discard: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := runHistoryCase(t, c, n)
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.endLen != 1 {
				t.Errorf("WebSocketEnd saw %d messages, want only the last one", a.endLen)
			}
		})
	}
}

// TestWebSocketDataDiscardHistoryTrimDoesNotAllocate: replacing the current message
// allocates nothing beyond the new message itself.
func TestWebSocketDataDiscardHistoryTrimDoesNotAllocate(t *testing.T) {
	d := newWebSocketData(true)
	d.addMessage(websocket.TextMessage, nil, true) // the first message allocates the one-entry list
	allocs := testing.AllocsPerRun(1000, func() {
		d.addMessage(websocket.TextMessage, nil, true)
	})
	if allocs != 1 {
		t.Fatalf("addMessage made %v allocations per message, want 1 (the message itself)", allocs)
	}
	if len(d.Messages) != 1 || d.MessageCount != 1002 {
		t.Fatalf("after 1002 messages: len(Messages) = %d, MessageCount = %d; want 1 and 1002", len(d.Messages), d.MessageCount)
	}
}

// TestWebSocketDataDiscardHistoryReleasesDroppedMessages: once a newer message
// replaces it, the old message is unreachable from the flow and is freed.
func TestWebSocketDataDiscardHistoryReleasesDroppedMessages(t *testing.T) {
	d := newWebSocketData(true)
	freed := make(chan struct{})
	first := d.addMessage(websocket.BinaryMessage, make([]byte, 64<<10), true)
	runtime.SetFinalizer(first, func(*WebSocketMessage) { close(freed) })
	first = nil
	d.addMessage(websocket.BinaryMessage, []byte("second"), false)

	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		// d stays reachable, as an open flow's WebSocketData is, so only
		// what d drops can be freed.
		runtime.KeepAlive(d)
		select {
		case <-freed:
			return
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the replaced message is still reachable from the flow")
		}
	}
}

// BenchmarkWebSocketMessageHistory measures how much heap one open WebSocket
// flow holds after relaying many messages, by default and with
// DiscardWebSocketHistory. Run it with:
//
//	go test -run '^$' -bench WebSocketMessageHistory -benchtime 1x ./proxy/
func BenchmarkWebSocketMessageHistory(b *testing.B) {
	log.SetLevel(log.ErrorLevel)
	const (
		messages = 2000
		size     = 16 << 10
	)
	for _, c := range []struct {
		name    string
		addr    string
		discard bool
	}{
		{"default", ":29124", false},
		{"DiscardWebSocketHistory", ":29125", true},
	} {
		b.Run(c.name, func(b *testing.B) {
			upgrader := websocket.Upgrader{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				for {
					mt, msg, err := conn.ReadMessage()
					if err != nil {
						return
					}
					if err := conn.WriteMessage(mt, msg); err != nil {
						return
					}
				}
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)

			proxy, err := NewProxy(&Options{Addr: c.addr, DiscardWebSocketHistory: c.discard})
			if err != nil {
				b.Fatal(err)
			}
			go proxy.Start()
			defer proxy.Close()
			time.Sleep(100 * time.Millisecond)
			proxyURL, _ := url.Parse("http://127.0.0.1" + c.addr)
			dialer := &websocket.Dialer{Proxy: http.ProxyURL(proxyURL), HandshakeTimeout: 5 * time.Second}
			payload := make([]byte, size)

			var totalDelta float64
			for i := 0; i < b.N; i++ {
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)

				conn, _, err := dialer.Dial("ws://"+u.Host+"/ws", nil)
				if err != nil {
					b.Fatal(err)
				}
				for j := 0; j < messages; j++ {
					if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
						b.Fatal(err)
					}
					if _, _, err := conn.ReadMessage(); err != nil {
						b.Fatal(err)
					}
				}
				// Every echo has arrived, so the proxy has recorded all
				// 2*messages frames on the still-open flow.
				runtime.GC()
				runtime.ReadMemStats(&after)
				totalDelta += float64(int64(after.HeapAlloc) - int64(before.HeapAlloc))
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				conn.Close()
				time.Sleep(50 * time.Millisecond)
			}
			b.ReportMetric(totalDelta/float64(b.N)/(1<<20), "heap-MiB/flow")
		})
	}
}
