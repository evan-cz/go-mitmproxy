package proxy

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// testBidiWebSocketHandler drains client frames while independently pushing its
// own frames to the client on a tight loop. Unlike an echo server, its
// server->client frames are NOT causally ordered after client frames, so both
// proxy relay goroutines append to the shared flow at the same time — the
// condition required to expose the unsynchronized observer read.
func testBidiWebSocketHandler() func(*websocket.Conn) {
	return func(conn *websocket.Conn) {
		defer conn.Close()

		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()

		for {
			select {
			case <-done:
				return
			default:
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte("server push frame")); err != nil {
				return
			}
		}
	}
}

// accessorObserverAddon mirrors the bundled observers (LogAddon, web UI) after
// the fix: it reads the flow's messages through the locked accessors rather than
// touching f.WebSocket.Messages directly. Under simultaneous bidirectional
// traffic this must be race-free — that is exactly the guarantee LastMessage /
// Len provide. Reverting either accessor to an unlocked read makes this test
// fail under `go test -race`, which is what gives it teeth.
type accessorObserverAddon struct {
	BaseAddon
}

func (a *accessorObserverAddon) WebSocketMessage(f *Flow) {
	last, _ := f.WebSocket.LastMessage()
	if last == nil {
		return
	}
	_ = last.FromClient
	_ = len(last.Content)
}

func (a *accessorObserverAddon) WebSocketEnd(f *Flow) {
	_ = f.WebSocket.Len()
}

// TestWebSocketObserverRace drives simultaneous bidirectional traffic with an
// observer addon enabled. The observer reads f.WebSocket.Messages without a lock
// while the opposite-direction relay goroutine appends under wsData.mu — a data
// race that `go test -race` must flag. Run with:
//
//	go test -race -run TestWebSocketObserverRace ./proxy/
func TestWebSocketObserverRace(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testBidiWebSocketHandler())
	defer wsServer.Close()

	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29097"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	proxy.AddAddon(&accessorObserverAddon{})
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	proxyURL, _ := url.Parse("http://127.0.0.1:29097")
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		HandshakeTimeout: time.Second * 5,
	}

	wsEndpoint := "ws://" + wsURL.Host + "/ws"
	conn, resp, err := dialer.Dial(wsEndpoint, nil)
	if err != nil {
		t.Fatalf("Failed to dial WS via proxy: %v, response: %v", err, resp)
	}
	defer conn.Close()

	var writerWg, readerWg sync.WaitGroup
	stop := make(chan struct{})

	// client -> server: push frames continuously
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte("client push frame")); err != nil {
				return
			}
		}
	}()

	// server -> client: drain frames continuously
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// let bidirectional traffic interleave long enough to trip the detector
	time.Sleep(time.Millisecond * 300)

	close(stop)
	writerWg.Wait() // no client writes in flight before we close
	conn.Close()    // unblocks the reader
	readerWg.Wait()
}
