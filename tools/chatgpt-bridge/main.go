// ARTEX ChatGPT plan bridge. Uses only the Go standard library.
// The bridge is a LOCAL development tool, not a public authentication gateway.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	authURL      = "https://auth.openai.com/api/accounts/authorize"
	tokenURL     = "https://auth.openai.com/api/accounts/oauth/token"
	discoveryURL = "https://auth.openai.com/.well-known/openid-configuration"
	resourceURL  = "https://api.openai.com/v1"
	scopes       = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
	maxRequest   = 20 << 20
)

type credentials struct {
	HostID       string    `json:"ext_agent_host_id"`
	ClientID     string    `json:"client_id"`
	Subject      string    `json:"subject"`
	Email        string    `json:"email"`
	IDToken      string    `json:"id_token"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
	BridgeKey    string    `json:"bridge_key"`
}
type oauthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}
type service struct {
	mu              sync.Mutex
	file            string
	cred            credentials
	authClient      *http.Client
	inferenceClient *http.Client
	api             string
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	state, err := defaultStateFile()
	if err != nil {
		log.Fatal(err)
	}
	command := os.Args[1]
	f := flag.NewFlagSet(command, flag.ExitOnError)
	file := f.String("state", state, "private credentials file path")
	listen := f.String("listen", "127.0.0.1:18765", "proxy bind address (serve only)")
	_ = f.Parse(os.Args[2:])
	s := &service{file: *file, authClient: &http.Client{Timeout: 25 * time.Second},
		inferenceClient: &http.Client{}, api: resourceURL}
	if err := s.load(); err != nil {
		log.Fatal(err)
	}
	switch command {
	case "login":
		if err := s.login(); err != nil {
			log.Fatal("sign-in failed: ", err)
		}
		fmt.Println("ChatGPT sign-in successful. The OAuth credentials were saved privately.")
		fmt.Println("Run 'go run . token' to display the separate ARTEX bridge key.")
	case "token":
		if s.cred.BridgeKey == "" {
			log.Fatal("run login first")
		}
		fmt.Println(s.cred.BridgeKey)
	case "status":
		if s.cred.AccessToken == "" {
			fmt.Println("Not signed in")
			return
		}
		fmt.Printf("Signed in: %s; plan scope: %v; token expires: %s\n",
			s.cred.Email, hasScope(s.cred.Scope, "chatgpt.tokens.use.direct"), s.cred.ExpiresAt.Local().Format(time.RFC3339))
	case "logout":
		if err := s.logout(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Local ChatGPT session cleared. Revoke the app in ChatGPT Settings if needed.")
	case "serve":
		if s.cred.AccessToken == "" || !hasScope(s.cred.Scope, "chatgpt.tokens.use.direct") {
			log.Fatal("run login and grant ChatGPT plan use first")
		}
		if s.cred.BridgeKey == "" {
			log.Fatal("missing bridge key; run login")
		}
		addr, err := net.ResolveTCPAddr("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		if addr.IP == nil || !addr.IP.IsLoopback() {
			log.Println("WARNING: non-loopback bind. Restrict inbound connections in the host firewall.")
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"status":"ok"}`)
		})
		mux.HandleFunc("GET /v1/models", s.authorized(s.models))
		mux.HandleFunc("POST /v1/responses", s.authorized(s.responses))
		server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
		log.Printf("Listening at http://%s/v1 (ChatGPT plan; no API-key billing)", *listen)
		log.Fatal(server.ListenAndServe())
	default:
		usage()
		os.Exit(2)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "Usage: artex-chatgpt-bridge <login|token|status|logout|serve> [--listen host:port] [--state path]")
}
func defaultStateFile() (string, error) {
	d, e := os.UserConfigDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "artex-chatgpt-bridge", "credentials.json"), nil
}
func randomText(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func hasScope(scopes, name string) bool {
	for _, s := range strings.Fields(scopes) {
		if s == name {
			return true
		}
	}
	return false
}

func (s *service) load() error {
	b, e := os.ReadFile(s.file)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(b, &s.cred)
}
func (s *service) save() error {
	if err := os.MkdirAll(filepath.Dir(s.file), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.cred, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.file), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// Windows does not allow Rename to replace an existing file consistently.
	if runtime.GOOS == "windows" {
		if err := os.Remove(s.file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(tmp.Name(), s.file)
}
func openBrowser(link string) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", link)
	case "darwin":
		c = exec.Command("open", link)
	default:
		c = exec.Command("xdg-open", link)
	}
	return c.Start()
}
func (s *service) login() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cred.HostID == "" {
		s.cred.HostID = "urn:uuid:" + uuidV4()
	}
	if s.cred.BridgeKey == "" {
		s.cred.BridgeKey = randomText(32)
	}
	// Persist the host identity before initiating dynamic registration.
	if err := s.save(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	redirect := "http://127.0.0.1:" + fmt.Sprint(ln.Addr().(*net.TCPAddr).Port) + "/auth/callback"
	state, nonce, verifier := randomText(32), randomText(32), randomText(48)
	sum := sha256.Sum256([]byte(verifier))
	clientID := s.cred.ClientID
	if clientID == "" {
		clientID = "dynamic_agent_client"
	}
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {scopes}, "resource": {resourceURL}, "state": {state}, "nonce": {nonce},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"ext_agent_host_id": {s.cred.HostID}}
	if clientID == "dynamic_agent_client" {
		q.Set("agent_name_hint", "ARTEX ChatGPT Bridge")
	} else if s.cred.IDToken != "" {
		q.Set("id_token_hint", s.cred.IDToken)
	}
	type callback struct {
		code, clientID, oauthError string
		err                        error
	}
	result := make(chan callback, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(state)) != 1 {
			http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
			return
		}
		c := callback{code: r.URL.Query().Get("code"), clientID: r.URL.Query().Get("client_id"), oauthError: r.URL.Query().Get("error")}
		if c.code == "" && c.oauthError == "" {
			c.err = errors.New("authorization code not provided")
		}
		select {
		case result <- c:
		default:
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ChatGPT authorization received. Return to the terminal.")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(ln) }()
	defer server.Shutdown(context.Background())
	fmt.Println("Open the browser to sign in with ChatGPT and approve plan access.")
	fmt.Println("If this is your first sign-in, you can paste the link below into your browser:")
	authorize := authURL + "?" + q.Encode()
	// May contain id_token_hint; do NOT log the URL after this interactive display.
	if clientID == "dynamic_agent_client" {
		fmt.Println(authorize) // no retained ID token in a first-time registration URL
	} else {
		fmt.Println("Reauthorization URL contains an account hint and is intentionally not printed.")
	}
	if err := openBrowser(authorize); err != nil {
		fmt.Fprintln(os.Stderr, "Browser launch failed:", err)
	}
	var cb callback
	select {
	case cb = <-result:
	case <-time.After(5 * time.Minute):
		return errors.New("authorization timed out")
	}
	if cb.err != nil {
		return cb.err
	}
	if cb.oauthError != "" {
		return errors.New("authorization declined: " + cb.oauthError)
	}
	issued := clientID
	if clientID == "dynamic_agent_client" {
		issued = cb.clientID
		if issued == "" || issued == "dynamic_agent_client" {
			return errors.New("registration returned no issued client ID")
		}
	} else if cb.clientID != "" && cb.clientID != issued {
		return errors.New("unexpected client ID on reauthorization")
	}
	t, err := s.exchange(url.Values{"grant_type": {"authorization_code"}, "client_id": {issued},
		"code": {cb.code}, "code_verifier": {verifier}, "redirect_uri": {redirect}, "resource": {resourceURL}})
	if err != nil {
		return err
	}
	if !hasScope(t.Scope, "chatgpt.tokens.use.direct") {
		return errors.New("ChatGPT plan usage scope was not granted")
	}
	subject, email, err := s.verifyIDToken(t.IDToken, issued, nonce)
	if err != nil {
		return err
	}
	if s.cred.Subject != "" && s.cred.Subject != subject {
		return errors.New("different account returned on reauthorization; sign out first")
	}
	if t.RefreshToken == "" {
		return errors.New("no renewable session: offline_access not granted")
	}
	s.cred.ClientID = issued
	s.cred.Subject = subject
	s.cred.Email = email
	s.cred.IDToken = t.IDToken
	s.cred.AccessToken = t.AccessToken
	s.cred.RefreshToken = t.RefreshToken
	s.cred.Scope = t.Scope
	s.cred.ExpiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	return s.save()
}
func uuidV4() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func (s *service) exchange(v url.Values) (oauthTokens, error) {
	resp, err := s.authClient.PostForm(tokenURL, v)
	if err != nil {
		return oauthTokens{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return oauthTokens{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return oauthTokens{}, fmt.Errorf("OAuth token exchange: HTTP %d: %s", resp.StatusCode, string(raw))
	}
	var t oauthTokens
	if err = json.Unmarshal(raw, &t); err != nil {
		return t, err
	}
	if t.AccessToken == "" || t.TokenType != "Bearer" || t.ExpiresIn <= 0 {
		return t, errors.New("invalid OAuth token response")
	}
	return t, nil
}
func (s *service) accessToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !hasScope(s.cred.Scope, "chatgpt.tokens.use.direct") {
		return "", errors.New("ChatGPT plan access not authorized")
	}
	if time.Until(s.cred.ExpiresAt) > 3*time.Minute {
		return s.cred.AccessToken, nil
	}
	if s.cred.RefreshToken == "" || s.cred.ClientID == "" {
		return "", errors.New("session expired; run login")
	}
	t, err := s.exchange(url.Values{"grant_type": {"refresh_token"}, "client_id": {s.cred.ClientID},
		"refresh_token": {s.cred.RefreshToken}, "resource": {resourceURL}})
	if err != nil {
		return "", fmt.Errorf("token refresh failed; run login: %w", err)
	}
	if !hasScope(t.Scope, "chatgpt.tokens.use.direct") {
		return "", errors.New("renewed token lacks ChatGPT plan scope")
	}
	if t.RefreshToken == "" {
		return "", errors.New("refresh token rotation missing")
	}
	s.cred.AccessToken = t.AccessToken
	s.cred.RefreshToken = t.RefreshToken
	s.cred.Scope = t.Scope
	s.cred.ExpiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	if t.IDToken != "" {
		s.cred.IDToken = t.IDToken
	}
	if err = s.save(); err != nil {
		return "", err
	}
	return s.cred.AccessToken, nil
}
func (s *service) logout() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cred.RefreshToken != "" {
		// Best effort revocation; never print or log the token.
		cfg, err := s.openIDConfig()
		if err == nil && cfg.RevocationEndpoint != "" {
			resp, e := s.authClient.PostForm(cfg.RevocationEndpoint, url.Values{"token": {s.cred.RefreshToken},
				"token_type_hint": {"refresh_token"}, "client_id": {s.cred.ClientID}})
			if e == nil {
				resp.Body.Close()
				if resp.StatusCode != 200 {
					fmt.Fprintln(os.Stderr, "Warning: remote revocation not confirmed")
				}
			}
			if e != nil {
				fmt.Fprintln(os.Stderr, "Warning: remote revocation not confirmed:", e)
			}
		} else {
			fmt.Fprintln(os.Stderr, "Warning: unable to confirm remote revocation")
		}
	}
	host, key := s.cred.HostID, s.cred.BridgeKey
	clientID, subject, email := s.cred.ClientID, s.cred.Subject, s.cred.Email
	s.cred = credentials{HostID: host, BridgeKey: key, ClientID: clientID, Subject: subject, Email: email}
	return s.save()
}

type oidcConfig struct {
	Issuer             string `json:"issuer"`
	JWKSURI            string `json:"jwks_uri"`
	RevocationEndpoint string `json:"revocation_endpoint"`
}

func (s *service) openIDConfig() (oidcConfig, error) {
	resp, err := s.authClient.Get(discoveryURL)
	if err != nil {
		return oidcConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return oidcConfig{}, fmt.Errorf("OpenID discovery: %s", resp.Status)
	}
	var cfg oidcConfig
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg)
	if cfg.Issuer != "https://auth.openai.com" || !strings.HasPrefix(cfg.JWKSURI, "https://auth.openai.com/") {
		return cfg, errors.New("unexpected OpenID issuer or JWKS URI")
	}
	return cfg, err
}
func (s *service) verifyIDToken(token, clientID, nonce string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", errors.New("invalid ID token")
	}
	decode := func(p string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(p) }
	h, e := decode(parts[0])
	if e != nil {
		return "", "", e
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if e = json.Unmarshal(h, &hdr); e != nil || hdr.Alg != "RS256" || hdr.Kid == "" {
		return "", "", errors.New("unsupported ID token signing algorithm/key")
	}
	cfg, e := s.openIDConfig()
	if e != nil {
		return "", "", e
	}
	resp, e := s.authClient.Get(cfg.JWKSURI)
	if e != nil {
		return "", "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", errors.New("JWKS unavailable")
	}
	var keys struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&keys); e != nil {
		return "", "", e
	}
	var pub *rsa.PublicKey
	for _, k := range keys.Keys {
		if k.Kid != hdr.Kid || k.Kty != "RSA" {
			continue
		}
		nb, e1 := decode(k.N)
		eb, e2 := decode(k.E)
		if e1 != nil || e2 != nil {
			return "", "", errors.New("bad JWKS encoding")
		}
		n := new(big.Int).SetBytes(nb)
		ex := new(big.Int).SetBytes(eb)
		if !ex.IsInt64() || ex.Int64() < 3 || ex.Int64() > 1<<31 {
			return "", "", errors.New("invalid RSA exponent")
		}
		pub = &rsa.PublicKey{N: n, E: int(ex.Int64())}
		break
	}
	if pub == nil {
		return "", "", errors.New("ID token signing key not found")
	}
	sig, e := decode(parts[2])
	if e != nil {
		return "", "", e
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if e = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig); e != nil {
		return "", "", errors.New("ID token signature invalid")
	}
	p, e := decode(parts[1])
	if e != nil {
		return "", "", e
	}
	var claims struct {
		Issuer string          `json:"iss"`
		Sub    string          `json:"sub"`
		Aud    json.RawMessage `json:"aud"`
		Nonce  string          `json:"nonce"`
		Email  string          `json:"email"`
		Exp    int64           `json:"exp"`
		Nbf    int64           `json:"nbf"`
	}
	if e = json.Unmarshal(p, &claims); e != nil {
		return "", "", e
	}
	var aud string
	_ = json.Unmarshal(claims.Aud, &aud)
	validAud := aud == clientID
	if !validAud {
		var list []string
		_ = json.Unmarshal(claims.Aud, &list)
		for _, a := range list {
			if a == clientID {
				validAud = true
			}
		}
	}
	now := time.Now().Unix()
	if claims.Issuer != "https://auth.openai.com" || !validAud || claims.Nonce != nonce || claims.Sub == "" || claims.Exp <= now || claims.Nbf > now+60 {
		return "", "", errors.New("ID token issuer/audience/nonce/time validation failed")
	}
	return claims.Sub, claims.Email, nil
}
func (s *service) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.cred.BridgeKey)) != 1 {
			http.Error(w, "Bridge authentication required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
func (s *service) models(w http.ResponseWriter, r *http.Request) {
	token, err := s.accessToken()
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), "GET", s.api+"/models", nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.inferenceClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		copyResponse(w, resp)
		return
	}
	var result struct {
		Models []struct {
			Slug        string `json:"slug"`
			DisplayName string `json:"display_name"`
			Visibility  string `json:"visibility"`
		} `json:"models"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	data := make([]map[string]string, 0, len(result.Models))
	for _, m := range result.Models {
		if m.Slug != "" && (m.Visibility == "list" || m.Visibility == "") {
			data = append(data, map[string]string{"id": m.Slug, "object": "model", "name": m.DisplayName})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
}
func (s *service) responses(w http.ResponseWriter, r *http.Request) {
	token, err := s.accessToken()
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
	if err != nil {
		http.Error(w, "request too large or unreadable", 413)
		return
	}
	fixed, err := normalizeRequest(body)
	if err != nil {
		http.Error(w, "unsupported ARTEX Responses request: "+err.Error(), 400)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), "POST", s.api+"/responses", bytes.NewReader(fixed))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := s.inferenceClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		copyResponse(w, resp)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if bytes.HasPrefix(line, []byte("data:")) {
				payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
				if len(payload) > 0 && string(payload) != "[DONE]" {
					if transformed, e := rewriteEvent(payload); e == nil {
						line = append(append([]byte("data: "), transformed...), '\n')
					}
				}
			}
			if _, e := w.Write(line); e != nil {
				return
			}
			flusher.Flush()
		}
		if err != nil {
			return
		}
	}
}
func copyResponse(w http.ResponseWriter, r *http.Response) {
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.WriteHeader(r.StatusCode)
	io.Copy(w, io.LimitReader(r.Body, 2<<20))
}

// ChatGPT-plan Responses preview requires a stateless streamed request with
// namespaced tools. ARTEX/Norma already uses Responses; only normalize the
// differences without altering the evidence/history or tool argument schemas.
func normalizeRequest(raw []byte) ([]byte, error) {
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("expected JSON object")
	}
	// Unsupported in the ChatGPT-plan preview; remove rather than send a known 400.
	for _, k := range []string{"background", "conversation", "max_output_tokens", "max_tool_calls", "metadata", "moderation", "multi_agent", "prompt", "prompt_cache_retention", "safety_identifier", "temperature", "top_logprobs", "top_p", "truncation", "user", "previous_response_id"} {
		delete(p, k)
	}
	p["store"] = false
	p["stream"] = true
	rawInput, ok := p["input"].([]any)
	if !ok {
		return nil, errors.New("input must be a full-history array")
	}
	input := make([]any, 0, len(rawInput))
	instructions, _ := p["instructions"].(string)
	for _, entry := range rawInput {
		item, ok := entry.(map[string]any)
		if !ok {
			return nil, errors.New("input item must be an object")
		}
		role, _ := item["role"].(string)
		if role == "system" {
			instructions += "\n\n" + plainText(item["content"])
			continue
		}
		if item["type"] == "function_call" {
			if _, ok := item["namespace"]; !ok {
				item["namespace"] = "artex"
			}
		}
		input = append(input, item)
	}
	if strings.TrimSpace(instructions) != "" {
		p["instructions"] = strings.TrimSpace(instructions)
	}
	p["input"] = input
	if rawTools, exists := p["tools"]; exists {
		tools, ok := rawTools.([]any)
		if !ok {
			return nil, errors.New("tools must be an array")
		}
		if len(tools) > 0 {
			for _, t := range tools {
				obj, ok := t.(map[string]any)
				if !ok || obj["type"] != "function" {
					return nil, errors.New("only local function tools are supported")
				}
			}
			p["tools"] = []any{map[string]any{"type": "namespace", "name": "artex",
				"description": "Local tools supplied by ARTEX. The ARTEX host executes tool calls with its configured safety and scope restrictions.", "tools": tools}}
		}
	}
	if choice, ok := p["tool_choice"].(map[string]any); ok && choice["type"] == "function" {
		choice["namespace"] = "artex"
	}
	return json.Marshal(p)
}
func plainText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	var b strings.Builder
	if list, ok := v.([]any); ok {
		for _, c := range list {
			if m, ok := c.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					b.WriteString(t)
					b.WriteString("\n")
				}
			}
		}
	}
	return b.String()
}

// The official API may include a "namespace" on function_call items; Norma's
// flat function registry expects only the original name and call_id. Strip
// only that namespace field in function_call objects, not model text or data.
func rewriteEvent(raw []byte) ([]byte, error) {
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return raw, err
	}
	stripNamespace(data)
	return json.Marshal(data)
}
func stripNamespace(v any) {
	switch x := v.(type) {
	case map[string]any:
		if x["type"] == "function_call" {
			if x["namespace"] == "artex" {
				delete(x, "namespace")
			}
		}
		for _, child := range x {
			stripNamespace(child)
		}
	case []any:
		for _, child := range x {
			stripNamespace(child)
		}
	}
}
