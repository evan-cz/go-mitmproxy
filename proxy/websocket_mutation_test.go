package proxy

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// rewriteModifierAddon implements WebSocketMessageModifier. It rewrites or drops
// client->server frames according to its config, leaving server->client frames
// untouched so an echo server round-trips the (mutated) payload back to us.
type rewriteModifierAddon struct {
	BaseAddon
	rewrite      map[string]string // client payload -> replacement
	dropContains string            // drop any client frame containing this
}

func (a *rewriteModifierAddon) RewriteWebSocketMessage(f *Flow, msg *WebSocketMessage) {
	if !msg.FromClient {
		return
	}
	if a.dropContains != "" && strings.Contains(string(msg.Content), a.dropContains) {
		msg.Drop()
		return
	}
	if to, ok := a.rewrite[string(msg.Content)]; ok {
		msg.Content = []byte(to)
	}
}

// dialWSViaProxy connects to wsURL through a proxy listening on proxyAddr.
func dialWSViaProxy(t *testing.T, proxyAddr, wsHost string) *websocket.Conn {
	t.Helper()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyURL(proxyURL),
		HandshakeTimeout: time.Second * 5,
	}
	conn, resp, err := dialer.Dial("ws://"+wsHost+"/ws", nil)
	if err != nil {
		t.Fatalf("Failed to dial WS via proxy: %v, response: %v", err, resp)
	}
	return conn
}

// TestWebSocketRewriteLonger proves an addon can rewrite a client frame to a
// payload of a DIFFERENT (longer) length and have it forwarded — the case the
// library cannot do today, because it forwards the originally captured bytes.
func TestWebSocketRewriteLonger(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testEchoWebSocketHandler(t))
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29098"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	proxy.AddAddon(&rewriteModifierAddon{rewrite: map[string]string{"hello": "a much longer world"}})
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29098", wsURL.Host)
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	_, received, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read echoed message: %v", err)
	}

	if string(received) != "a much longer world" {
		t.Fatalf("Expected rewritten %q, got %q", "a much longer world", string(received))
	}
}

// TestWebSocketRewriteVariants covers equal-length (worked before via slice
// aliasing; must still work) and shorter (guards length assumptions) rewrites.
func TestWebSocketRewriteVariants(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	cases := []struct {
		name       string
		from, to   string
		listenAddr string
	}{
		{"equal length", "foo", "bar", ":29099"},
		{"shorter", "hello", "hi", ":29100"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wsServer := testWebSocketServer(t, testEchoWebSocketHandler(t))
			defer wsServer.Close()
			wsURL, err := url.Parse(wsServer.URL)
			if err != nil {
				t.Fatalf("Failed to parse WS server URL: %v", err)
			}

			proxy, err := NewProxy(&Options{Addr: tc.listenAddr})
			if err != nil {
				t.Fatalf("Failed to create proxy: %v", err)
			}
			proxy.AddAddon(&rewriteModifierAddon{rewrite: map[string]string{tc.from: tc.to}})
			go proxy.Start()
			defer proxy.Close()
			time.Sleep(time.Millisecond * 100)

			conn := dialWSViaProxy(t, "127.0.0.1"+tc.listenAddr, wsURL.Host)
			defer conn.Close()

			if err := conn.WriteMessage(websocket.TextMessage, []byte(tc.from)); err != nil {
				t.Fatalf("Failed to send message: %v", err)
			}
			conn.SetReadDeadline(time.Now().Add(time.Second * 3))
			_, received, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("Failed to read echoed message: %v", err)
			}
			if string(received) != tc.to {
				t.Fatalf("Expected rewritten %q, got %q", tc.to, string(received))
			}
		})
	}
}

// TestWebSocketDrop proves an addon calling Drop swallows the frame (it never
// reaches the peer) while the connection stays healthy for later frames.
func TestWebSocketDrop(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testEchoWebSocketHandler(t))
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29101"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	proxy.AddAddon(&rewriteModifierAddon{dropContains: "SECRET"})
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29101", wsURL.Host)
	defer conn.Close()

	// This frame must be dropped: the echo server never sees it, never echoes it.
	if err := conn.WriteMessage(websocket.TextMessage, []byte("SECRET payload")); err != nil {
		t.Fatalf("Failed to send dropped message: %v", err)
	}
	// This frame must round-trip, proving the connection is still healthy.
	if err := conn.WriteMessage(websocket.TextMessage, []byte("normal")); err != nil {
		t.Fatalf("Failed to send normal message: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	_, received, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read echoed message: %v", err)
	}
	// If the dropped frame had leaked through, the first echo would be "SECRET payload".
	if string(received) != "normal" {
		t.Fatalf("Expected first echo %q (dropped frame must not leak), got %q", "normal", string(received))
	}

	// Drain: no second echo should ever arrive (the SECRET frame was dropped,
	// so the echo server never saw it and never echoed it back).
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 300))
	if _, extra, err := conn.ReadMessage(); err == nil {
		t.Fatalf("Dropped frame leaked: got unexpected second echo %q", string(extra))
	}
}

// testEchoAndPushWSHandler echoes client frames AND independently pushes its own
// distinct frames on a tight loop, forcing both relay goroutines to append
// concurrently. Used to prove message identity holds under bidirectional load.
func testEchoAndPushWSHandler() func(*websocket.Conn) {
	return func(conn *websocket.Conn) {
		defer conn.Close()
		var writeMu sync.Mutex // gorilla forbids concurrent writes to one conn
		write := func(mt int, data []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return conn.WriteMessage(mt, data)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				mt, msg, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if err := write(mt, msg); err != nil {
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
			if err := write(websocket.TextMessage, []byte("SERVER_PUSH")); err != nil {
				return
			}
		}
	}
}

// TestWebSocketMutationIdentityBidirectional proves the modifier acts on the
// exact frame being forwarded (retained pointer), not Messages[len-1], under
// simultaneous bidirectional traffic. The modifier rewrites ONLY client frames
// (prefixing "C:"); server-pushed frames must arrive verbatim. If identity came
// from len-1, a server push could be misidentified as a client frame (arriving
// as "C:SERVER_PUSH") or a client echo could miss its rewrite. Run with -race.
func TestWebSocketMutationIdentityBidirectional(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testEchoAndPushWSHandler())
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29102"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	proxy.AddAddon(&prefixClientModifierAddon{})
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29102", wsURL.Host)
	defer conn.Close()

	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
				return
			}
		}
	}()

	var gotClient, gotServer int
	deadline := time.Now().Add(time.Millisecond * 400)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		switch string(msg) {
		case "C:ping": // client frame, correctly rewritten and echoed back
			gotClient++
		case "SERVER_PUSH": // server frame, correctly left untouched
			gotServer++
		default:
			t.Fatalf("message identity violated: unexpected frame %q", string(msg))
		}
	}

	close(stop)
	<-writerDone

	// Guard against a vacuous pass: both directions must have been observed, so
	// the "no unexpected frame" assertion above actually exercised both paths.
	if gotClient == 0 {
		t.Fatalf("never observed a rewritten client frame (C:ping); test proved nothing")
	}
	if gotServer == 0 {
		t.Fatalf("never observed an untouched server frame (SERVER_PUSH); test proved nothing")
	}
}

// prefixClientModifierAddon rewrites only client->server frames by prefixing
// "C:", relying on the FromClient of the exact frame being forwarded.
type prefixClientModifierAddon struct {
	BaseAddon
}

func (a *prefixClientModifierAddon) RewriteWebSocketMessage(f *Flow, msg *WebSocketMessage) {
	if msg.FromClient {
		msg.Content = append([]byte("C:"), msg.Content...)
	}
}

// contentReadingObserver mirrors the bundled observers (LogAddon, web UI): it
// reads the latest message's Content via the locked accessor.
type contentReadingObserver struct {
	BaseAddon
}

func (o *contentReadingObserver) WebSocketMessage(f *Flow) {
	last, _ := f.WebSocket.LastMessage()
	if last == nil {
		return
	}
	_ = len(last.Content) // read the payload, as LogAddon/web UI do
}

// mutatingModifier rewrites every frame's Content.
type mutatingModifier struct {
	BaseAddon
}

func (m *mutatingModifier) RewriteWebSocketMessage(f *Flow, msg *WebSocketMessage) {
	msg.Content = append([]byte("M:"), msg.Content...)
}

// TestWebSocketModifierObserverRace is the regression guard for the race a
// modifier reopens: an observer reading a frame's Content via LastMessage can
// receive the OTHER direction's frame (global-last), while that direction's
// modifier mutates the same frame's Content. Observer read and modifier write
// must never touch the same object. Run with -race; fails before the working-
// copy fix, passes after.
func TestWebSocketModifierObserverRace(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testEchoAndPushWSHandler())
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29103"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	proxy.AddAddon(&contentReadingObserver{})
	proxy.AddAddon(&mutatingModifier{})
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29103", wsURL.Host)
	defer conn.Close()

	var writerWg, readerWg sync.WaitGroup
	stop := make(chan struct{})

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
			if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
				return
			}
		}
	}()

	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	time.Sleep(time.Millisecond * 300)
	close(stop)
	writerWg.Wait()
	conn.Close()
	readerWg.Wait()
}

// testServerPushSeqWSHandler pushes a fixed sequence of frames to the client on
// connect (server-originated, no client prompt), then drains client frames.
// Used to exercise the server->client modifier/drop path.
func testServerPushSeqWSHandler(payloads ...string) func(*websocket.Conn) {
	return func(conn *websocket.Conn) {
		defer conn.Close()
		for _, p := range payloads {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(p)); err != nil {
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

// serverRewriteModifierAddon rewrites or drops only server->client frames,
// exercising the S->C relay branch (mirror of rewriteModifierAddon).
type serverRewriteModifierAddon struct {
	BaseAddon
	rewrite      map[string]string
	dropContains string
}

func (a *serverRewriteModifierAddon) RewriteWebSocketMessage(f *Flow, msg *WebSocketMessage) {
	if msg.FromClient {
		return
	}
	if a.dropContains != "" && strings.Contains(string(msg.Content), a.dropContains) {
		msg.Drop()
		return
	}
	if to, ok := a.rewrite[string(msg.Content)]; ok {
		msg.Content = []byte(to)
	}
}

// TestWebSocketServerRewrite proves the server->client relay branch honors a
// modifier's payload rewrite (the C->S rewrite tests never exercise this
// direction, since their modifiers act only on client frames).
func TestWebSocketServerRewrite(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testServerPushSeqWSHandler("SERVER_SECRET"))
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29104"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	proxy.AddAddon(&serverRewriteModifierAddon{rewrite: map[string]string{"SERVER_SECRET": "REDACTED"}})
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29104", wsURL.Host)
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	_, received, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read server-pushed message: %v", err)
	}
	if string(received) != "REDACTED" {
		t.Fatalf("Expected server frame rewritten to %q, got %q", "REDACTED", string(received))
	}
}

// TestWebSocketServerDrop proves the server->client relay branch honors Drop:
// the dropped server frame never reaches the client, and the next server frame
// still arrives (connection stays healthy).
func TestWebSocketServerDrop(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testServerPushSeqWSHandler("DROP_ME", "keep"))
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29105"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	proxy.AddAddon(&serverRewriteModifierAddon{dropContains: "DROP_ME"})
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29105", wsURL.Host)
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	_, received, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read message: %v", err)
	}
	if string(received) != "keep" {
		t.Fatalf("Expected first delivered frame %q (dropped frame must not leak), got %q", "keep", string(received))
	}

	// No further frame should arrive: the only other server frame was dropped.
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 300))
	if _, extra, err := conn.ReadMessage(); err == nil {
		t.Fatalf("Dropped frame leaked to client: got unexpected frame %q", string(extra))
	}
}

// observeThenModifyAddon both observes (recording what WebSocketMessage sees)
// and modifies (rewriting client frames), to verify observers see the ORIGINAL
// payload, never a modifier's rewrite.
type observeThenModifyAddon struct {
	BaseAddon
	mu       sync.Mutex
	observed []string
}

func (a *observeThenModifyAddon) WebSocketMessage(f *Flow) {
	last, _ := f.WebSocket.LastMessage()
	if last == nil || !last.FromClient {
		return
	}
	a.mu.Lock()
	a.observed = append(a.observed, string(last.Content))
	a.mu.Unlock()
}

func (a *observeThenModifyAddon) RewriteWebSocketMessage(f *Flow, msg *WebSocketMessage) {
	if msg.FromClient {
		msg.Content = []byte("REWRITTEN")
	}
}

// TestWebSocketObserverSeesOriginal proves an addon that both observes and
// modifies records the original payload, while the peer receives the rewritten
// one. The recorded frame is never mutated (modifiers work on a copy).
func TestWebSocketObserverSeesOriginal(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testEchoWebSocketHandler(t))
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29106"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	addon := &observeThenModifyAddon{}
	proxy.AddAddon(addon)
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29106", wsURL.Host)
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("orig")); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	_, received, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read echoed message: %v", err)
	}
	if string(received) != "REWRITTEN" {
		t.Fatalf("Peer should receive rewritten payload; got %q", string(received))
	}

	addon.mu.Lock()
	observed := append([]string(nil), addon.observed...)
	addon.mu.Unlock()
	// The client's "orig" frame must have been observed as "orig", not "REWRITTEN".
	foundOrig := false
	for _, o := range observed {
		if o == "REWRITTEN" {
			t.Fatalf("observer saw a rewritten payload %q; observers must see the original", o)
		}
		if o == "orig" {
			foundOrig = true
		}
	}
	if !foundOrig {
		t.Fatalf("observer never saw the original client payload; observed=%v", observed)
	}
}

// prependModifierAddon prepends a prefix to client frames' Content.
type prependModifierAddon struct {
	BaseAddon
	prefix string
}

func (a *prependModifierAddon) RewriteWebSocketMessage(f *Flow, msg *WebSocketMessage) {
	if msg.FromClient {
		msg.Content = append([]byte(a.prefix), msg.Content...)
	}
}

// TestWebSocketModifierChaining proves multiple modifiers run in addon order on
// the same working copy: a later modifier sees an earlier one's rewrite.
func TestWebSocketModifierChaining(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testEchoWebSocketHandler(t))
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29107"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	// First rewrites "start" -> "A"; second must then see "A" and produce "B:A".
	proxy.AddAddon(&rewriteModifierAddon{rewrite: map[string]string{"start": "A"}})
	proxy.AddAddon(&prependModifierAddon{prefix: "B:"})
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29107", wsURL.Host)
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("start")); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	_, received, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read echoed message: %v", err)
	}
	if string(received) != "B:A" {
		t.Fatalf("Expected chained rewrite %q, got %q", "B:A", string(received))
	}
}

// recordMutationAddon rewrites client frames, then verifies (still inside the
// serialized hook) that the mutation landed on the RECORDED frame itself: the
// pointer LastMessage returns is the one it mutated, and its Content is the new
// value. This is what makes the record faithful to what was forwarded.
type recordMutationAddon struct {
	BaseAddon
	mu         sync.Mutex
	seen       bool
	recordedOK bool
}

func (a *recordMutationAddon) RewriteWebSocketMessage(f *Flow, msg *WebSocketMessage) {
	if !msg.FromClient {
		return
	}
	msg.Content = []byte("REWRITTEN")
	last, _ := f.WebSocket.LastMessage()
	a.mu.Lock()
	a.seen = true
	a.recordedOK = last == msg && string(last.Content) == "REWRITTEN"
	a.mu.Unlock()
}

// TestWebSocketRecordReflectsMutation proves a modifier mutates the recorded
// frame in place, so f.WebSocket reflects what was forwarded (the observability
// goal of the serialized relay), and the peer receives the rewrite.
func TestWebSocketRecordReflectsMutation(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testEchoWebSocketHandler(t))
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29108"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	addon := &recordMutationAddon{}
	proxy.AddAddon(addon)
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29108", wsURL.Host)
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("orig")); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	_, received, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read echoed message: %v", err)
	}
	if string(received) != "REWRITTEN" {
		t.Fatalf("peer should receive rewrite; got %q", string(received))
	}

	addon.mu.Lock()
	seen, ok := addon.seen, addon.recordedOK
	addon.mu.Unlock()
	if !seen {
		t.Fatal("modifier never ran on a client frame")
	}
	if !ok {
		t.Fatal("recorded frame does not reflect the mutation (record is not faithful)")
	}
}

// recordDropAddon drops client frames, then verifies the recorded frame reports
// IsDropped so consumers can distinguish forwarded frames from dropped ones.
type recordDropAddon struct {
	BaseAddon
	mu              sync.Mutex
	seen            bool
	recordedDropped bool
}

func (a *recordDropAddon) RewriteWebSocketMessage(f *Flow, msg *WebSocketMessage) {
	if !msg.FromClient {
		return
	}
	msg.Drop()
	last, _ := f.WebSocket.LastMessage()
	a.mu.Lock()
	a.seen = true
	a.recordedDropped = last.IsDropped()
	a.mu.Unlock()
}

// TestWebSocketRecordReflectsDrop proves a dropped frame is recorded as dropped
// (IsDropped) and is not forwarded to the peer.
func TestWebSocketRecordReflectsDrop(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	wsServer := testWebSocketServer(t, testEchoWebSocketHandler(t))
	defer wsServer.Close()
	wsURL, err := url.Parse(wsServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse WS server URL: %v", err)
	}

	proxy, err := NewProxy(&Options{Addr: ":29109"})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	addon := &recordDropAddon{}
	proxy.AddAddon(addon)
	go proxy.Start()
	defer proxy.Close()
	time.Sleep(time.Millisecond * 100)

	conn := dialWSViaProxy(t, "127.0.0.1:29109", wsURL.Host)
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte("drop me")); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// The frame was dropped, so the echo server never sees it: no reply arrives.
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 300))
	if _, extra, err := conn.ReadMessage(); err == nil {
		t.Fatalf("dropped frame was forwarded: got echo %q", string(extra))
	}

	addon.mu.Lock()
	seen, dropped := addon.seen, addon.recordedDropped
	addon.mu.Unlock()
	if !seen {
		t.Fatal("modifier never ran on a client frame")
	}
	if !dropped {
		t.Fatal("recorded frame does not report IsDropped after Drop")
	}
}

// TestWebSocketMessageMarshalJSONDropped verifies drop status is exposed in the
// JSON alias, and omitted when false so default output is unchanged.
func TestWebSocketMessageMarshalJSONDropped(t *testing.T) {
	m := newWebSocketMessage(1, []byte("hi"), true)

	b, err := m.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "dropped") {
		t.Fatalf("dropped must be omitted when false; got %s", b)
	}

	m.Drop()
	b, err = m.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"dropped":true`) {
		t.Fatalf("expected dropped:true in JSON; got %s", b)
	}
}

// TestWebSocketDataAccessorsEmpty locks the contract the observer nil-guards
// depend on: LastMessage returns (nil, -1) and Len returns 0 when empty, and
// both report the correct last message/index/count once populated.
func TestWebSocketDataAccessorsEmpty(t *testing.T) {
	ws := newWebSocketData()

	if last, idx := ws.LastMessage(); last != nil || idx != -1 {
		t.Fatalf("empty LastMessage() = (%v, %d), want (nil, -1)", last, idx)
	}
	if n := ws.Len(); n != 0 {
		t.Fatalf("empty Len() = %d, want 0", n)
	}

	ws.addMessage(1, []byte("a"), true)
	ws.addMessage(1, []byte("bb"), false)

	last, idx := ws.LastMessage()
	if last == nil || string(last.Content) != "bb" || idx != 1 {
		t.Fatalf("LastMessage() = (%v, %d), want (bb, 1)", last, idx)
	}
	if n := ws.Len(); n != 2 {
		t.Fatalf("Len() = %d, want 2", n)
	}
}
