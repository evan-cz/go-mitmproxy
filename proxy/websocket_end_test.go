package proxy

import (
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// endAddon records how many messages the flow held when WebSocketEnd ran,
// and whether any WebSocketMessage hook ran after it. Its hook pauses briefly
// for server messages, so the server -> client direction is still busy when
// the client closes.
type endAddon struct {
	BaseAddon
	ended     chan struct{}
	endedFlag atomic.Bool
	late      atomic.Bool
	flow      *Flow
	count     int
}

func (a *endAddon) WebSocketMessage(f *Flow) {
	if a.endedFlag.Load() {
		a.late.Store(true)
	}
	if !f.WebSocket.Messages[len(f.WebSocket.Messages)-1].FromClient {
		time.Sleep(time.Millisecond)
	}
}

func (a *endAddon) WebSocketEnd(f *Flow) {
	a.flow = f
	a.count = len(f.WebSocket.Messages)
	a.endedFlag.Store(true)
	close(a.ended)
}

func startEndTestProxy(t *testing.T, addr string, a Addon) *websocket.Dialer {
	t.Helper()
	proxy, err := NewProxy(&Options{Addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	proxy.AddAddon(a)
	go proxy.Start()
	t.Cleanup(func() { proxy.Close() })
	time.Sleep(100 * time.Millisecond)
	proxyURL, _ := url.Parse("http://127.0.0.1" + addr)
	return &websocket.Dialer{Proxy: http.ProxyURL(proxyURL), HandshakeTimeout: 5 * time.Second}
}

func waitForEnd(t *testing.T, a *endAddon, timeout time.Duration) {
	t.Helper()
	select {
	case <-a.ended:
	case <-time.After(timeout):
		t.Fatalf("WebSocketEnd did not run within %v", timeout)
	}
}

// TestWebSocketEndSeesEveryMessage has both peers send continuously, then
// closes the client. WebSocketEnd must run only after both directions have
// stopped, so no message hook may run after it and the list it sees is final.
func TestWebSocketEndSeesEveryMessage(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, func(conn *websocket.Conn) {
		defer conn.Close()
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for {
			if err := conn.WriteMessage(websocket.TextMessage, []byte("server message")); err != nil {
				return
			}
		}
	})
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	end := &endAddon{ended: make(chan struct{})}
	dialer := startEndTestProxy(t, ":29079", end)
	conn, _, err := dialer.Dial("ws://"+wsURL.Host+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte("client message")); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	conn.Close()
	wg.Wait()

	waitForEnd(t, end, 10*time.Second)
	// Give the relay time to record anything it was still handling.
	time.Sleep(200 * time.Millisecond)
	if end.late.Load() {
		t.Fatal("a WebSocketMessage hook ran after WebSocketEnd")
	}
	if got := len(end.flow.WebSocket.Messages); got != end.count {
		t.Fatalf("WebSocketEnd saw %d messages, but the flow ended up with %d", end.count, got)
	}
}

// TestWebSocketEndWhenPeerStopsReading fills the connection to a client that
// stops reading, then has the client send a close message. The proxy's
// server -> client direction is then stuck writing to the client. WebSocketEnd
// must still run, after webSocketEndWait.
func TestWebSocketEndWhenPeerStopsReading(t *testing.T) {
	log.SetLevel(log.ErrorLevel)
	defer func(d time.Duration) { webSocketEndWait = d }(webSocketEndWait)
	webSocketEndWait = 200 * time.Millisecond

	big := make([]byte, 64<<10)
	wsServer := testWebSocketServer(t, func(conn *websocket.Conn) {
		defer conn.Close()
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for {
			if err := conn.WriteMessage(websocket.BinaryMessage, big); err != nil {
				return
			}
		}
	})
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	end := &endAddon{ended: make(chan struct{})}
	dialer := startEndTestProxy(t, ":29078", end)
	conn, _, err := dialer.Dial("ws://"+wsURL.Host+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Never read, so the buffers toward the client fill and the proxy's
	// write to the client blocks. Then end the client -> server direction.
	time.Sleep(500 * time.Millisecond)
	if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
		t.Fatal(err)
	}

	waitForEnd(t, end, 5*time.Second)
}
