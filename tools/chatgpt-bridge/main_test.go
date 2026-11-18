package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeRequest(t *testing.T) {
	input := `{
  "model":"gpt-6.1-sol", "instructions":"Original instructions",
  "input":[
   {"type":"message","role":"system","content":"System rules"},
   {"type":"message","role":"user","content":[{"type":"input_text","text":"Hello"}]},
   {"type":"function_call","call_id":"call123","name":"nmap","arguments":"{}"},
   {"type":"function_call_output","call_id":"call123","output":"done"}
  ],
  "tools":[{"type":"function","name":"nmap","description":"Scan one host","parameters":{"type":"object","properties":{}}}],
  "store":true,"stream":false,"temperature":0.5,"max_output_tokens":1000,"previous_response_id":"resp123"
 }`
	b, e := normalizeRequest([]byte(input))
	if e != nil {
		t.Fatal(e)
	}
	var got map[string]any
	if e = json.Unmarshal(b, &got); e != nil {
		t.Fatal(e)
	}
	if got["stream"] != true || got["store"] != false {
		t.Fatalf("must force streaming/stateless mode: %s", b)
	}
	for _, k := range []string{"temperature", "max_output_tokens", "previous_response_id"} {
		if _, exists := got[k]; exists {
			t.Fatalf("unsupported field %q passed", k)
		}
	}
	if !strings.Contains(got["instructions"].(string), "System rules") {
		t.Fatal("system instruction was dropped")
	}
	messages := got["input"].([]any)
	if len(messages) != 3 {
		t.Fatalf("expected 3 items, got %d", len(messages))
	}
	if messages[1].(map[string]any)["namespace"] != "artex" {
		t.Fatal("history call must be namespaced")
	}
	tools := got["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["type"] != "namespace" {
		t.Fatalf("tools must be grouped: %s", b)
	}
	if tools[0].(map[string]any)["tools"].([]any)[0].(map[string]any)["name"] != "nmap" {
		t.Fatal("original tool name not preserved")
	}
}
func TestUnsupportedToolsAreRejected(t *testing.T) {
	_, e := normalizeRequest([]byte(`{"input":[],"tools":[{"type":"mcp","server_label":"example"}]}`))
	if e == nil {
		t.Fatal("unsupported hosted tool must be rejected")
	}
}
func TestNoHistoryRejected(t *testing.T) {
	_, e := normalizeRequest([]byte(`{"input":"hello"}`))
	if e == nil {
		t.Fatal("string input must be rejected (preview requires full-history array)")
	}
}
func TestRewriteNamespaceInFunctionCallsOnly(t *testing.T) {
	raw := []byte(`{"type":"response.output_item.done","item":{"type":"function_call","name":"nmap","namespace":"artex","call_id":"x"},"message":"artex namespace should remain","trace":{"namespace":"artex"}}`)
	out, e := rewriteEvent(raw)
	if e != nil {
		t.Fatal(e)
	}
	var result map[string]any
	if e = json.Unmarshal(out, &result); e != nil {
		t.Fatal(e)
	}
	item := result["item"].(map[string]any)
	if _, ok := item["namespace"]; ok {
		t.Fatal("function call namespace was not stripped")
	}
	if result["trace"].(map[string]any)["namespace"] != "artex" {
		t.Fatal("unrelated object was modified")
	}
	if result["message"] != "artex namespace should remain" {
		t.Fatal("text was modified")
	}
}
func TestScopeExactMatch(t *testing.T) {
	if hasScope("openid resource.invoke chatgpt.tokens.use.direct", "chatgpt.tokens.use") {
		t.Fatal("scope prefix must not match")
	}
	if !hasScope("openid resource.invoke chatgpt.tokens.use.direct", "chatgpt.tokens.use.direct") {
		t.Fatal("exact scope should match")
	}
}

func TestBridgeStreamingRoundTrip(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("unexpected upstream path: %s", r.URL.Path)
			http.Error(w, "bad path", 404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer oauth-token" {
			t.Errorf("upstream did not receive OAuth bearer token")
		}
		var payload map[string]any
		if e := json.NewDecoder(r.Body).Decode(&payload); e != nil {
			t.Errorf("decode request: %v", e)
			return
		}
		if payload["store"] != false || payload["stream"] != true {
			t.Errorf("invalid plan request: %#v", payload)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: response.output_item.done\n")
		fmt.Fprint(w, "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"namespace\":\"artex\",\"name\":\"echo\",\"call_id\":\"a\",\"arguments\":\"{}\"}}\n\n")
	}))
	defer upstream.Close()
	svc := &service{cred: credentials{BridgeKey: "local-key", AccessToken: "oauth-token", Scope: "chatgpt.tokens.use.direct", ExpiresAt: time.Now().Add(time.Hour)}, api: upstream.URL, inferenceClient: &http.Client{}}
	app := httptest.NewServer(http.HandlerFunc(svc.authorized(svc.responses)))
	defer app.Close()
	req, e := http.NewRequest(http.MethodPost, app.URL+"/v1/responses", strings.NewReader(`{"input":[{"role":"user","content":"test"}],"tools":[{"type":"function","name":"echo","parameters":{"type":"object"}}]}`))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Authorization", "Bearer local-key")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	got, e := io.ReadAll(resp.Body)
	if e != nil {
		t.Fatal(e)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, got)
	}
	if strings.Contains(string(got), `"namespace"`) {
		t.Fatalf("namespace leaked to Norma: %s", got)
	}
	if !strings.Contains(string(got), `"name":"echo"`) {
		t.Fatalf("function tool call lost: %s", got)
	}
}
