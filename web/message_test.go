package web

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
)

// flowWithConnCtx builds a minimal proxy.Flow with a ConnContext (so
// ConnContext.Id() is usable) and the given WebSocket data.
func flowWithConnCtx(ws *proxy.WebSocketData) *proxy.Flow {
	return &proxy.Flow{
		Id:          uuid.New(),
		ConnContext: &proxy.ConnContext{ClientConn: &proxy.ClientConn{Id: uuid.New()}},
		WebSocket:   ws,
	}
}

// TestNewMessageFlowWebSocketMessage covers the web UI's migration to
// LastMessage(): the nil/empty guards must error, and the populated case must
// report the last message together with its matching index.
func TestNewMessageFlowWebSocketMessage(t *testing.T) {
	t.Run("nil WebSocket errors", func(t *testing.T) {
		f := flowWithConnCtx(nil)
		if _, err := newMessageFlow(messageTypeWebSocketMessage, f); err == nil {
			t.Fatal("expected error for nil WebSocket, got nil")
		}
	})

	t.Run("empty Messages errors", func(t *testing.T) {
		f := flowWithConnCtx(&proxy.WebSocketData{})
		if _, err := newMessageFlow(messageTypeWebSocketMessage, f); err == nil {
			t.Fatal("expected error for empty Messages, got nil")
		}
	})

	t.Run("populated reports last message and matching index", func(t *testing.T) {
		ws := &proxy.WebSocketData{Messages: []*proxy.WebSocketMessage{
			{Type: 1, Content: []byte("first"), FromClient: true},
			{Type: 1, Content: []byte("second"), FromClient: false},
		}}
		f := flowWithConnCtx(ws)

		msg, err := newMessageFlow(messageTypeWebSocketMessage, f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var payload map[string]interface{}
		if err := json.Unmarshal(msg.content, &payload); err != nil {
			t.Fatalf("content is not valid JSON: %v", err)
		}
		if idx, ok := payload["msgIndex"].(float64); !ok || int(idx) != 1 {
			t.Fatalf("msgIndex = %v, want 1", payload["msgIndex"])
		}
		// The reported message must be the last one (index 1), i.e. "second".
		message, ok := payload["message"].(map[string]interface{})
		if !ok {
			t.Fatalf("message field missing or wrong type: %v", payload["message"])
		}
		// Content is base64-encoded []byte in the marshaled alias.
		if message["content"] == nil {
			t.Fatalf("message content missing: %v", message)
		}
	})
}

// TestNewMessageFlowWebSocketEnd covers the migration of the end message to
// Len(): messageCount must reflect the number of recorded frames.
func TestNewMessageFlowWebSocketEnd(t *testing.T) {
	ws := &proxy.WebSocketData{Messages: []*proxy.WebSocketMessage{
		{Type: 1, Content: []byte("a"), FromClient: true},
		{Type: 1, Content: []byte("b"), FromClient: false},
		{Type: 1, Content: []byte("c"), FromClient: true},
	}}
	f := flowWithConnCtx(ws)

	msg, err := newMessageFlow(messageTypeWebSocketEnd, f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(msg.content, &payload); err != nil {
		t.Fatalf("content is not valid JSON: %v", err)
	}
	if count, ok := payload["messageCount"].(float64); !ok || int(count) != 3 {
		t.Fatalf("messageCount = %v, want 3", payload["messageCount"])
	}
}
