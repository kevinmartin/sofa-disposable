package gatestatus

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	headSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func appKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func validResult() Result {
	return Result{
		PRNumber: 2, HeadSHA: headSHA, BaseSHA: baseSHA,
		State: Success, RunURL: "https://github.com/kevinmartin/sofa-disposable/actions/runs/12345",
		Description: "Hosted E2E suite passed",
	}
}

func currentPR(head, base, headRepo, baseRepo string) string {
	encoded, _ := json.Marshal(map[string]any{
		"number": 2, "state": "open",
		"head": map[string]any{"sha": head, "repo": map[string]string{"full_name": headRepo}},
		"base": map[string]any{"sha": base, "repo": map[string]string{"full_name": baseRepo}},
	})
	return string(encoded)
}

func TestPublishUsesSofaOnlyStatusTokenAndCurrentRevision(t *testing.T) {
	var calls []string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls = append(calls, req.Method+" "+req.URL.Path)
		switch req.URL.Path {
		case "/repos/kevinmartin/sofa/installation":
			if req.Method != http.MethodGet || !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer eyJ") {
				t.Fatal("installation lookup did not use App JWT")
			}
			return response(200, `{"id":42}`), nil
		case "/app/installations/42/access_tokens":
			if req.Method != http.MethodPost || !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer eyJ") {
				t.Fatal("token mint did not use App JWT")
			}
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Repositories) != 1 || body.Repositories[0] != "sofa" ||
				len(body.Permissions) != 2 || body.Permissions["statuses"] != "write" || body.Permissions["metadata"] != "read" {
				t.Fatalf("token scope widened: %#v", body)
			}
			return response(201, `{"token":"scoped-status-token"}`), nil
		case "/repos/kevinmartin/sofa/pulls/2":
			if req.Method != http.MethodGet || req.Header.Get("Authorization") != "Bearer read-only-token" {
				t.Fatal("PR read did not use independent read token")
			}
			return response(200, currentPR(headSHA, baseSHA, sofaRepository, sofaRepository)), nil
		case "/repos/kevinmartin/sofa/statuses/" + headSHA:
			if req.Method != http.MethodPost || req.Header.Get("Authorization") != "Bearer scoped-status-token" {
				t.Fatal("status did not use scoped App token")
			}
			var body struct {
				State       State  `json:"state"`
				TargetURL   string `json:"target_url"`
				Description string `json:"description"`
				Context     string `json:"context"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.State != Success || body.Context != statusContext || body.TargetURL != validResult().RunURL || body.Description != validResult().Description {
				t.Fatalf("unexpected status body: %#v", body)
			}
			return response(201, `{}`), nil
		default:
			t.Fatalf("unexpected API path %q", req.URL.Path)
			return nil, nil
		}
	})}
	w := Writer{Client: client, AppID: "123", PrivateKeyPEM: appKey(t), ReadToken: "read-only-token", Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
	if err := w.Publish(context.Background(), validResult()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 {
		t.Fatalf("expected four bounded calls, got %v", calls)
	}
}

func TestPublishRejectsStaleOrForeignPRWithoutStatus(t *testing.T) {
	cases := []struct {
		name     string
		head     string
		base     string
		headRepo string
		baseRepo string
	}{
		{"stale head", baseSHA, baseSHA, sofaRepository, sofaRepository},
		{"stale base", headSHA, headSHA, sofaRepository, sofaRepository},
		{"fork head", headSHA, baseSHA, "other/sofa", sofaRepository},
		{"foreign base", headSHA, baseSHA, sofaRepository, "other/sofa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statusCalls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/repos/kevinmartin/sofa/installation":
					return response(200, `{"id":42}`), nil
				case "/app/installations/42/access_tokens":
					return response(201, `{"token":"scoped-status-token"}`), nil
				case "/repos/kevinmartin/sofa/pulls/2":
					return response(200, currentPR(tc.head, tc.base, tc.headRepo, tc.baseRepo)), nil
				default:
					statusCalls++
					return response(201, `{}`), nil
				}
			})}
			w := Writer{Client: client, AppID: "123", PrivateKeyPEM: appKey(t)}
			if err := w.Publish(context.Background(), validResult()); err == nil {
				t.Fatal("expected current PR identity rejection")
			}
			if statusCalls != 0 {
				t.Fatalf("published status after identity rejection: %d calls", statusCalls)
			}
		})
	}
}

func TestPublishWithoutAppCredentialsMakesNoRequest(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(200, `{}`), nil
	})}
	for _, w := range []Writer{
		{Client: client},
		{Client: client, AppID: "123"},
		{Client: client, PrivateKeyPEM: appKey(t)},
		{Client: client, AppID: "not-an-ID", PrivateKeyPEM: appKey(t)},
	} {
		if err := w.Publish(context.Background(), validResult()); err == nil {
			t.Fatal("expected missing or invalid App credentials to fail")
		}
	}
	if calls != 0 {
		t.Fatalf("made %d API calls without valid App credentials", calls)
	}
}

func TestRejectsInvalidStatusSourceBeforeNetwork(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Result)
	}{
		{"wrong run repository", func(r *Result) { r.RunURL = "https://github.com/other/repo/actions/runs/12345" }},
		{"external run host", func(r *Result) { r.RunURL = "https://example.com/kevinmartin/sofa-disposable/actions/runs/12345" }},
		{"query on run URL", func(r *Result) { r.RunURL += "?redirect=bad" }},
		{"overlong description", func(r *Result) { r.Description = strings.Repeat("x", 141) }},
		{"unknown state", func(r *Result) { r.State = "error" }},
		{"invalid SHA", func(r *Result) { r.HeadSHA = "short" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := validResult()
			tc.edit(&result)
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(200, `{}`), nil
			})}
			w := Writer{Client: client, AppID: "123", PrivateKeyPEM: appKey(t)}
			if err := w.Publish(context.Background(), result); err == nil {
				t.Fatal("accepted invalid source")
			}
			if calls != 0 {
				t.Fatalf("made %d API calls with invalid status source", calls)
			}
		})
	}
}

func TestLatestRequiresAuthenticatedAppAndNewestMatchingContext(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statuses   string
		wantFound  bool
		wantSource bool
		wantState  State
	}{
		{"current App", `[{"context":"other","state":"success"},{"context":"sofa / hosted-e2e","state":"success","description":"exact suite","creator":{"login":"sofa-gate[bot]","type":"Bot"}}]`, true, true, Success},
		{"newer foreign status", `[{"context":"sofa / hosted-e2e","state":"success","description":"forged","creator":{"login":"other[bot]","type":"Bot"}},{"context":"sofa / hosted-e2e","state":"success","description":"exact suite","creator":{"login":"sofa-gate[bot]","type":"Bot"}}]`, true, false, Success},
		{"no gate status", `[{"context":"other","state":"success"}]`, false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/app":
					if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer eyJ") {
						t.Fatal("App identity was not requested with signed JWT")
					}
					return response(200, `{"id":123,"slug":"sofa-gate"}`), nil
				case "/repos/kevinmartin/sofa/commits/" + headSHA + "/statuses":
					if req.URL.Query().Get("per_page") != "100" || req.Header.Get("Authorization") != "Bearer read-token" {
						t.Fatal("status read used unexpected scope")
					}
					return response(200, tc.statuses), nil
				default:
					t.Fatalf("unexpected request %s", req.URL.Path)
					return nil, nil
				}
			})}
			w := Writer{Client: client, AppID: "123", PrivateKeyPEM: appKey(t), ReadToken: "read-token"}
			got, err := w.Latest(context.Background(), headSHA)
			if err != nil || got.Found != tc.wantFound || got.Source != tc.wantSource || got.State != tc.wantState {
				t.Fatalf("latest status = %+v, err=%v", got, err)
			}
		})
	}
}

func TestLatestFailsClosedOnIdentityOrReadError(t *testing.T) {
	for _, tc := range []struct {
		name      string
		appBody   string
		readCode  int
		readCalls int
	}{
		{"wrong App ID", `{"id":999,"slug":"sofa-gate"}`, 200, 0},
		{"status read unavailable", `{"id":123,"slug":"sofa-gate"}`, 503, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/app" {
					return response(200, tc.appBody), nil
				}
				reads++
				return response(tc.readCode, `[]`), nil
			})}
			w := Writer{Client: client, AppID: "123", PrivateKeyPEM: appKey(t)}
			if _, err := w.Latest(context.Background(), headSHA); err == nil || reads != tc.readCalls {
				t.Fatalf("untrusted status read was accepted: reads=%d err=%v", reads, err)
			}
		})
	}
}

func TestLatestRejectsFullStatusPageWithoutGateContext(t *testing.T) {
	statuses := make([]map[string]string, 100)
	for i := range statuses {
		statuses[i] = map[string]string{"context": "unrelated", "state": "success"}
	}
	page, _ := json.Marshal(statuses)
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/app" {
			return response(200, `{"id":123,"slug":"sofa-gate"}`), nil
		}
		return response(200, string(page)), nil
	})}
	w := Writer{Client: client, AppID: "123", PrivateKeyPEM: appKey(t)}
	if _, err := w.Latest(context.Background(), headSHA); err == nil || !strings.Contains(err.Error(), "outside bounded page") {
		t.Fatalf("ambiguous status page was accepted: %v", err)
	}
}
