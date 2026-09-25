// Package gatestatus publishes the trusted hosted gate result to the exact
// sofa commit that was independently validated by the disposable observer.
package gatestatus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	sofaRepository = "kevinmartin/sofa"
	statusContext  = "sofa / hosted-e2e"
	apiURL         = "https://api.github.com"
)

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// State is a GitHub commit-status state supported by the hosted gate.
type State string

const (
	Pending State = "pending"
	Success State = "success"
	Failure State = "failure"
)

// Result must come from the trusted observer after independent validation.
// Publish verifies its PR revision against GitHub again before writing status.
type Result struct {
	PRNumber    int
	HeadSHA     string
	BaseSHA     string
	State       State
	RunURL      string
	Description string
}

// Writer uses a GitHub App installed on sofa. ReadToken is optional for public
// sofa PRs; if sofa becomes private, supply a separate read-only credential.
// The App token itself is always restricted to sofa and status publication.
type Writer struct {
	Client        *http.Client
	AppID         string
	PrivateKeyPEM string
	ReadToken     string
	Now           func() time.Time
}

// Snapshot describes the latest status in sofa's gate context. Source is true
// only when GitHub attributes that status to this authenticated App's bot.
type Snapshot struct {
	Found       bool
	Source      bool
	State       State
	Description string
}

// Latest reads only a bounded first page. An ambiguous or unavailable page
// cannot justify preserving a previous green status.
func (w Writer) Latest(ctx context.Context, headSHA string) (Snapshot, error) {
	var snapshot Snapshot
	if !sha40.MatchString(headSHA) {
		return snapshot, errors.New("invalid sofa head SHA")
	}
	jwt, err := w.appJWT()
	if err != nil {
		return snapshot, err
	}
	var app struct {
		ID   int64  `json:"id"`
		Slug string `json:"slug"`
	}
	if err := w.request(ctx, http.MethodGet, "/app", jwt, nil, &app, http.StatusOK); err != nil {
		return snapshot, fmt.Errorf("read sofa App identity: %w", err)
	}
	configuredID, _ := strconv.ParseInt(w.AppID, 10, 64)
	if app.ID != configuredID || app.Slug == "" || strings.ContainsAny(app.Slug, "/\r\n") {
		return snapshot, errors.New("sofa App identity mismatch")
	}
	var statuses []struct {
		Context     string `json:"context"`
		State       State  `json:"state"`
		Description string `json:"description"`
		Creator     struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"creator"`
	}
	path := fmt.Sprintf("/repos/%s/commits/%s/statuses?per_page=100", sofaRepository, headSHA)
	if err := w.request(ctx, http.MethodGet, path, w.ReadToken, nil, &statuses, http.StatusOK); err != nil {
		return snapshot, fmt.Errorf("read sofa gate status: %w", err)
	}
	for _, status := range statuses {
		if status.Context != statusContext {
			continue
		}
		return Snapshot{
			Found:       true,
			Source:      status.Creator.Type == "Bot" && status.Creator.Login == app.Slug+"[bot]",
			State:       status.State,
			Description: status.Description,
		}, nil
	}
	if len(statuses) == 100 {
		return snapshot, errors.New("sofa gate status outside bounded page")
	}
	return snapshot, nil
}

// Publish fails closed when credentials, source identity, or the current PR
// revision do not match. It never includes credentials or response bodies in
// errors, and never sends a status to a candidate-selected repository.
func (w Writer) Publish(ctx context.Context, result Result) error {
	if err := validateResult(result); err != nil {
		return err
	}
	jwt, err := w.appJWT()
	if err != nil {
		return err
	}

	var installation struct {
		ID int64 `json:"id"`
	}
	if err := w.request(ctx, http.MethodGet, "/repos/"+sofaRepository+"/installation", jwt, nil, &installation, http.StatusOK); err != nil {
		return fmt.Errorf("find sofa App installation: %w", err)
	}
	if installation.ID <= 0 {
		return errors.New("invalid sofa App installation")
	}
	var credential struct {
		Token string `json:"token"`
	}
	request := struct {
		Repositories []string          `json:"repositories"`
		Permissions  map[string]string `json:"permissions"`
	}{
		Repositories: []string{"sofa"},
		Permissions:  map[string]string{"statuses": "write", "metadata": "read"},
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installation.ID)
	if err := w.request(ctx, http.MethodPost, path, jwt, request, &credential, http.StatusCreated); err != nil {
		return fmt.Errorf("mint sofa status token: %w", err)
	}
	if credential.Token == "" {
		return errors.New("empty sofa status token")
	}

	// Read the live PR using an independent read credential. A token restricted
	// to statuses:write must not silently gain pull-request read permission.
	var pr struct {
		Number int    `json:"number"`
		State  string `json:"state"`
		Head   struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
	}
	path = fmt.Sprintf("/repos/%s/pulls/%d", sofaRepository, result.PRNumber)
	if err := w.request(ctx, http.MethodGet, path, w.ReadToken, nil, &pr, http.StatusOK); err != nil {
		return fmt.Errorf("read current sofa PR: %w", err)
	}
	if pr.Number != result.PRNumber || pr.State != "open" ||
		pr.Head.Repo.FullName != sofaRepository || pr.Base.Repo.FullName != sofaRepository ||
		pr.Head.SHA != result.HeadSHA || pr.Base.SHA != result.BaseSHA {
		return errors.New("sofa PR revision or source identity changed")
	}

	status := struct {
		State       State  `json:"state"`
		TargetURL   string `json:"target_url"`
		Description string `json:"description"`
		Context     string `json:"context"`
	}{result.State, result.RunURL, result.Description, statusContext}
	path = fmt.Sprintf("/repos/%s/statuses/%s", sofaRepository, result.HeadSHA)
	if err := w.request(ctx, http.MethodPost, path, credential.Token, status, nil, http.StatusCreated); err != nil {
		return fmt.Errorf("publish sofa gate status: %w", err)
	}
	return nil
}

func validateResult(r Result) error {
	if r.PRNumber <= 0 || !sha40.MatchString(r.HeadSHA) || !sha40.MatchString(r.BaseSHA) {
		return errors.New("invalid sofa PR revision")
	}
	if r.State != Pending && r.State != Success && r.State != Failure {
		return errors.New("invalid gate status state")
	}
	if r.Description == "" || len(r.Description) > 140 || strings.ContainsAny(r.Description, "\r\n\x00") {
		return errors.New("invalid gate status description")
	}
	u, err := url.Parse(r.RunURL)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid hosted run URL")
	}
	const prefix = "/kevinmartin/sofa-disposable/actions/runs/"
	id := strings.TrimPrefix(u.Path, prefix)
	if !strings.HasPrefix(u.Path, prefix) || id == "" || strings.Trim(id, "0123456789") != "" {
		return errors.New("invalid hosted run URL")
	}
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		return errors.New("invalid hosted run URL")
	}
	return nil
}

func (w Writer) appJWT() (string, error) {
	if w.AppID == "" || w.PrivateKeyPEM == "" {
		return "", errors.New("sofa App credential unavailable")
	}
	if id, err := strconv.ParseInt(w.AppID, 10, 64); err != nil || id <= 0 {
		return "", errors.New("invalid sofa App ID")
	}
	block, _ := pem.Decode([]byte(w.PrivateKeyPEM))
	if block == nil {
		return "", errors.New("invalid sofa App key")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = parsed
	} else if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if key == nil {
		return "", errors.New("invalid sofa App RSA key")
	}
	now := time.Now()
	if w.Now != nil {
		now = w.Now()
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"iat": now.Unix() - 60, "exp": now.Unix() + 9*60, "iss": w.AppID})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	message := header + "." + payload
	hash := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", errors.New("sign sofa App credential")
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (w Writer) request(ctx context.Context, method, path, token string, input, output any, wantStatus int) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return errors.New("encode GitHub request")
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiURL+path, body)
	if err != nil {
		return errors.New("construct GitHub request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "sofa-disposable-gate-status")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	// Even a configured client must not follow a redirect with an App secret.
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := copyClient.Do(req)
	if err != nil {
		return errors.New("GitHub transport unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}
	if output != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(output); err != nil {
			return errors.New("invalid GitHub API response")
		}
	}
	return nil
}
