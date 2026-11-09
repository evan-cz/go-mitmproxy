package proxy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketPrependRecord(t *testing.T) {
	msg := newWebSocketMessage(websocket.TextMessage, []byte("current"), false)
	msg.Prepend([]byte("first"))
	msg.Drop()
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Before  []string `json:"before"`
		Dropped bool     `json:"dropped"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Before) != 1 || record.Before[0] != "first" || !record.Dropped {
		t.Fatalf("record lost forwarded payloads or drop status: %s", raw)
	}
}

type prependMessagesAddon struct {
	BaseAddon
	fromClient bool
	drop       bool
	observed   chan string
}

func (a *prependMessagesAddon) WebSocketMessage(f *Flow) {
	msg, _ := f.WebSocket.LastMessage()
	if msg.FromClient == a.fromClient {
		a.observed <- string(msg.Content)
	}
}

func (a *prependMessagesAddon) RewriteWebSocketMessage(_ *Flow, msg *WebSocketMessage) {
	if msg.FromClient != a.fromClient || string(msg.Content) != "current" {
		return
	}
	first := []byte("first")
	msg.Prepend(first)
	first[0] = 'X'
	msg.Prepend([]byte("second"))
	msg.Content = []byte("rewritten")
	if a.drop {
		msg.Drop()
	}
}

func TestWebSocketPrepend(t *testing.T) {
	for i, tc := range []struct {
		fromClient bool
		drop       bool
		opcode     int
	}{
		{true, false, websocket.TextMessage},
		{true, true, websocket.TextMessage},
		{false, false, websocket.TextMessage},
		{false, true, websocket.TextMessage},
		{true, false, websocket.BinaryMessage},
		{false, false, websocket.BinaryMessage},
	} {
		t.Run(fmt.Sprintf("client=%t/drop=%t/opcode=%d", tc.fromClient, tc.drop, tc.opcode), func(t *testing.T) {
			handler := testEchoWebSocketHandler(t)
			if !tc.fromClient {
				handler = func(conn *websocket.Conn) {
					defer conn.Close()
					for _, payload := range []string{"current", "sentinel"} {
						if err := conn.WriteMessage(tc.opcode, []byte(payload)); err != nil {
							return
						}
					}
					for {
						if _, _, err := conn.ReadMessage(); err != nil {
							return
						}
					}
				}
			}
			server := testWebSocketServer(t, handler)
			defer server.Close()
			serverURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", 29120+i)
			proxy, err := NewProxy(&Options{Addr: addr})
			if err != nil {
				t.Fatal(err)
			}
			addon := &prependMessagesAddon{fromClient: tc.fromClient, drop: tc.drop, observed: make(chan string, 10)}
			proxy.AddAddon(addon)
			go proxy.Start()
			defer proxy.Close()
			time.Sleep(100 * time.Millisecond)
			conn := dialWSViaProxy(t, addr, serverURL.Host)
			defer conn.Close()
			if tc.fromClient {
				for _, payload := range []string{"current", "sentinel"} {
					if err := conn.WriteMessage(tc.opcode, []byte(payload)); err != nil {
						t.Fatal(err)
					}
				}
			}
			want := []string{"first", "second"}
			if !tc.drop {
				want = append(want, "rewritten")
			}
			want = append(want, "sentinel")
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			for _, payload := range want {
				opcode, got, err := conn.ReadMessage()
				if err != nil {
					t.Fatal(err)
				}
				if opcode != tc.opcode || string(got) != payload {
					t.Fatalf("received (%d, %q), want (%d, %q)", opcode, got, tc.opcode, payload)
				}
			}
			for _, original := range []string{"current", "sentinel"} {
				select {
				case got := <-addon.observed:
					if got != original {
						t.Fatalf("observer received %q, want original %q", got, original)
					}
				case <-time.After(time.Second):
					t.Fatal("observer did not receive the original frame")
				}
			}
		})
	}
}
