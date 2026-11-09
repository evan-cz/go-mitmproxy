package proxy

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type retainMessagesAddon struct {
	BaseAddon
	fromClient bool
	held       []*WebSocketMessage
	observed   chan string
}

func (a *retainMessagesAddon) WebSocketMessage(f *Flow) {
	msg, _ := f.WebSocket.LastMessage()
	if msg.FromClient == a.fromClient {
		a.observed <- string(msg.Content)
	}
}

func (a *retainMessagesAddon) RewriteWebSocketMessage(_ *Flow, msg *WebSocketMessage) {
	if msg.FromClient == a.fromClient {
		a.held = append(a.held, &WebSocketMessage{Type: msg.Type, Content: append([]byte(nil), msg.Content...)})
		msg.Drop()
	}
}

func (a *retainMessagesAddon) FlushWebSocketMessages(_ *Flow, fromClient bool) []*WebSocketMessage {
	if fromClient != a.fromClient {
		return nil
	}
	held := a.held
	a.held = nil
	return held
}

func TestWebSocketFlushBeforeClose(t *testing.T) {
	for i, tc := range []struct {
		fromClient bool
		opcode     int
	}{
		{true, websocket.TextMessage},
		{false, websocket.TextMessage},
		{true, websocket.BinaryMessage},
		{false, websocket.BinaryMessage},
	} {
		t.Run(fmt.Sprintf("client=%t/opcode=%d", tc.fromClient, tc.opcode), func(t *testing.T) {
			received := make(chan *WebSocketMessage, 1)
			server := testWebSocketServer(t, func(conn *websocket.Conn) {
				defer conn.Close()
				if tc.fromClient {
					opcode, content, err := conn.ReadMessage()
					if err == nil {
						received <- &WebSocketMessage{Type: opcode, Content: content}
					}
					return
				}
				conn.WriteMessage(tc.opcode, []byte("held"))
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			})
			defer server.Close()
			serverURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", 29130+i)
			proxy, err := NewProxy(&Options{Addr: addr})
			if err != nil {
				t.Fatal(err)
			}
			addon := &retainMessagesAddon{fromClient: tc.fromClient, observed: make(chan string, 10)}
			proxy.AddAddon(addon)
			go proxy.Start()
			defer proxy.Close()
			time.Sleep(100 * time.Millisecond)
			conn := dialWSViaProxy(t, addr, serverURL.Host)
			defer conn.Close()
			if tc.fromClient {
				if err := conn.WriteMessage(tc.opcode, []byte("held")); err != nil {
					t.Fatal(err)
				}
				if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
					t.Fatal(err)
				}
			} else {
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				opcode, content, err := conn.ReadMessage()
				if err != nil {
					t.Fatalf("connection closed before retained message arrived: %v", err)
				}
				received <- &WebSocketMessage{Type: opcode, Content: content}
			}
			select {
			case msg := <-received:
				if msg.Type != tc.opcode || string(msg.Content) != "held" {
					t.Fatalf("flushed (%d, %q), want (%d, held)", msg.Type, msg.Content, tc.opcode)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("retained message did not reach the destination")
			}
			if got := <-addon.observed; got != "held" {
				t.Fatalf("observer received %q, want original held message", got)
			}
			select {
			case extra := <-addon.observed:
				t.Fatalf("flushed message re-entered observer hooks: %q", extra)
			default:
			}
		})
	}
}
