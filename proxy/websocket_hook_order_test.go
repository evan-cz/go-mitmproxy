package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// lastMessageAddon records, for every WebSocketMessage hook, the content of
// the last message in f.WebSocket.Messages. The hook is meant to describe the
// message that triggered it, so every message should appear here exactly once.
// It pauses briefly before reading, as a hook doing any work first would,
// which gives the other direction time to record a message in between.
type lastMessageAddon struct {
	BaseAddon
	mu   sync.Mutex
	seen []string
}

func (a *lastMessageAddon) WebSocketMessage(f *Flow) {
	time.Sleep(50 * time.Microsecond)
	last := f.WebSocket.Messages[len(f.WebSocket.Messages)-1]
	a.mu.Lock()
	a.seen = append(a.seen, string(last.Content))
	a.mu.Unlock()
}

// TestWebSocketHookSeesItsOwnMessage sends numbered messages from the client
// and the server at the same time. Without the two directions taking turns, a
// hook in one direction can run after the other direction has recorded a newer
// message, so one message is reported twice and another not at all.
func TestWebSocketHookSeesItsOwnMessage(t *testing.T) {
	log.SetLevel(log.ErrorLevel)
	const n = 500

	clientMessagesDone := make(chan struct{})
	wsServer := testWebSocketServer(t, func(conn *websocket.Conn) {
		defer conn.Close()
		go func() {
			defer close(clientMessagesDone)
			for i := 0; i < n; i++ {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for i := 0; i < n; i++ {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("s-%d", i))); err != nil {
				return
			}
		}
		<-clientMessagesDone
	})
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29089"})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &lastMessageAddon{}
	proxy.AddAddon(recorder)
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(100 * time.Millisecond)

	proxyURL, _ := url.Parse("http://127.0.0.1:29089")
	dialer := &websocket.Dialer{Proxy: http.ProxyURL(proxyURL), HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial("ws://"+wsURL.Host+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverMessagesDone := make(chan struct{})
	go func() {
		defer close(serverMessagesDone)
		for i := 0; i < n; i++ {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	for i := 0; i < n; i++ {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("c-%d", i))); err != nil {
			t.Fatal(err)
		}
	}

	// Each message's hooks run before it is forwarded, so once both
	// peers have received every message, every hook has run.
	for _, done := range []chan struct{}{clientMessagesDone, serverMessagesDone} {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for messages")
		}
	}

	recorder.mu.Lock()
	seen := append([]string(nil), recorder.seen...)
	recorder.mu.Unlock()
	sort.Strings(seen)
	want := make([]string, 0, 2*n)
	for i := 0; i < n; i++ {
		want = append(want, fmt.Sprintf("c-%d", i), fmt.Sprintf("s-%d", i))
	}
	sort.Strings(want)

	if len(seen) != len(want) {
		t.Fatalf("hooks ran %d times, want %d", len(seen), len(want))
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("hooks did not each see their own message: first mismatch at %d, saw %q, want %q", i, seen[i], want[i])
		}
	}
}
