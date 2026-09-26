// sofa-gate-cleanup is an opt-in, trusted default-branch tool for retiring
// superseded disposable suites. It never accepts a branch name from input.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kevinmartin/sofa-disposable/internal/gatecaller"
)

const (
	sofaRepo     = "kevinmartin/sofa"
	consumerRepo = "kevinmartin/sofa-disposable"
	workflowPath = ".github/workflows/sofa-gate.yml"
	fixturePath  = "fixture/greeting.go"
)

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var suiteBranch = regexp.MustCompile(`^sofa-e2e(?:-result)?/p[1-9][0-9]*-[0-9a-f]{24}$`)

type options struct {
	SofaPR                                     int
	CandidateSHA, PRBaseSHA, DisposableBaseSHA string
	CallerSHA, ResultSHA, CandidateDigest      string
	DraftPR                                    int
	Apply                                      bool
	AllowActive                                bool // only set by the trusted completed-result path
}

func parse(args []string) (options, error) {
	var o options
	f := flag.NewFlagSet("sofa-gate-cleanup", flag.ContinueOnError)
	f.IntVar(&o.SofaPR, "sofa-pr", 0, "")
	f.StringVar(&o.CandidateSHA, "candidate-sha", "", "")
	f.StringVar(&o.PRBaseSHA, "pr-base-sha", "", "")
	f.StringVar(&o.DisposableBaseSHA, "disposable-base-sha", "", "")
	f.StringVar(&o.CallerSHA, "caller-sha", "", "")
	f.StringVar(&o.ResultSHA, "result-sha", "", "")
	f.StringVar(&o.CandidateDigest, "candidate-digest", "", "")
	f.IntVar(&o.DraftPR, "draft-pr", 0, "")
	f.BoolVar(&o.Apply, "apply", false, "")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || o.SofaPR < 1 || o.DraftPR < 1 || !sha40.MatchString(o.CandidateSHA) || !sha40.MatchString(o.PRBaseSHA) || !sha40.MatchString(o.DisposableBaseSHA) || !sha40.MatchString(o.CallerSHA) || !sha40.MatchString(o.ResultSHA) || !sha64.MatchString(o.CandidateDigest) {
		return o, errors.New("complete exact suite identity and draft PR number required")
	}
	return o, nil
}

func (o options) suite() string {
	h := sha256.Sum256([]byte(o.CandidateSHA + ":" + o.PRBaseSHA + ":" + o.DisposableBaseSHA))
	return fmt.Sprintf("p%d-%x", o.SofaPR, h[:12])
}

func (o options) caller() string { return "sofa-e2e/" + o.suite() }
func (o options) result() string { return "sofa-e2e-result/" + o.suite() }

func (o options) callerContent() string {
	return gatecaller.BranchWorkflow(gatecaller.Pull{Number: o.SofaPR, HeadSHA: o.CandidateSHA, BaseSHA: o.PRBaseSHA}, o.DisposableBaseSHA)
}

type api struct {
	client     *http.Client
	token      string
	writeToken string
	base       string
}
type apiError int

func (e apiError) Error() string { return fmt.Sprintf("GitHub API returned HTTP %d", e) }

func (a api) call(ctx context.Context, method, path string, input, output any) error {
	if !strings.HasPrefix(path, "/repos/") || strings.ContainsAny(path, "\r\n#") {
		return errors.New("invalid GitHub API path")
	}
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "sofa-disposable-gate-cleanup")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return errors.New("GitHub transport unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiError(resp.StatusCode)
	}
	if output == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(output)
}

func (a api) get(ctx context.Context, path string, out any) error {
	return a.call(ctx, http.MethodGet, path, nil, out)
}
func (a api) patch(ctx context.Context, path string, in, out any) error {
	if a.writeToken == "" {
		return errors.New("trusted disposable publisher credential unavailable")
	}
	a.token = a.writeToken
	return a.call(ctx, http.MethodPatch, path, in, out)
}

type pull struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	Draft   bool   `json:"draft"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
	Head    struct {
		Ref, SHA string
		Repo     struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref, SHA string
		Repo     struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"base"`
}

func (a api) pull(ctx context.Context, repo string, number int) (pull, error) {
	var p pull
	err := a.get(ctx, fmt.Sprintf("/repos/%s/pulls/%d", repo, number), &p)
	if err != nil || p.Number != number {
		return p, errors.New("PR identity unavailable")
	}
	return p, nil
}

func (a api) ref(ctx context.Context, branch string) (string, error) {
	var r struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := a.get(ctx, "/repos/"+consumerRepo+"/git/ref/heads/"+url.PathEscape(branch), &r); err != nil {
		return "", err
	}
	if !sha40.MatchString(r.Object.SHA) {
		return "", errors.New("invalid reference head")
	}
	return r.Object.SHA, nil
}

func (a api) optionalRef(ctx context.Context, branch string) (string, bool, error) {
	sha, err := a.ref(ctx, branch)
	var e apiError
	if errors.As(err, &e) && e == http.StatusNotFound {
		return "", false, nil
	}
	return sha, err == nil, err
}

type commit struct {
	SHA, Message string
	Tree         struct {
		SHA string `json:"sha"`
	}
	Parents []struct {
		SHA string `json:"sha"`
	}
}

func (a api) commit(ctx context.Context, sha string) (commit, error) {
	var c commit
	if err := a.get(ctx, "/repos/"+consumerRepo+"/git/commits/"+sha, &c); err != nil {
		return c, err
	}
	if c.SHA != sha || !sha40.MatchString(c.Tree.SHA) {
		return c, errors.New("invalid commit identity")
	}
	return c, nil
}

type treeEntry struct{ Path, Mode, Type, SHA string }

func (a api) tree(ctx context.Context, sha string) (map[string]treeEntry, error) {
	var t struct {
		Tree      []treeEntry `json:"tree"`
		Truncated bool        `json:"truncated"`
	}
	if err := a.get(ctx, "/repos/"+consumerRepo+"/git/trees/"+sha+"?recursive=1", &t); err != nil {
		return nil, err
	}
	if t.Truncated || len(t.Tree) > 10000 {
		return nil, errors.New("tree unavailable or truncated")
	}
	m := make(map[string]treeEntry, len(t.Tree))
	for _, e := range t.Tree {
		if e.Type != "tree" {
			if _, ok := m[e.Path]; ok {
				return nil, errors.New("duplicate tree path")
			}
			m[e.Path] = e
		}
	}
	return m, nil
}

func (a api) singleChange(ctx context.Context, baseSHA, branchSHA, path string) error {
	base, err := a.commit(ctx, baseSHA)
	if err != nil {
		return err
	}
	branch, err := a.commit(ctx, branchSHA)
	if err != nil {
		return err
	}
	old, err := a.tree(ctx, base.Tree.SHA)
	if err != nil {
		return err
	}
	newTree, err := a.tree(ctx, branch.Tree.SHA)
	if err != nil {
		return err
	}
	if len(old) != len(newTree) {
		return errors.New("suite branch changes file count")
	}
	changed := 0
	for name, before := range old {
		after, ok := newTree[name]
		if !ok {
			return errors.New("suite branch removes a file")
		}
		if before != after {
			if name != path || before.Mode != "100644" || before.Type != "blob" || after.Mode != "100644" || after.Type != "blob" {
				return errors.New("suite branch changes an unrelated path")
			}
			changed++
		}
	}
	if changed != 1 {
		return errors.New("suite branch is not a one-file update")
	}
	return nil
}

func (a api) content(ctx context.Context, path, ref string) ([]byte, error) {
	var v struct{ Content, Encoding string }
	if err := a.get(ctx, "/repos/"+consumerRepo+"/contents/"+path+"?ref="+url.QueryEscape(ref), &v); err != nil {
		return nil, err
	}
	if v.Encoding != "base64" || len(v.Content) > 2<<20 {
		return nil, errors.New("invalid content encoding or size")
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(v.Content, "\n", ""))
}

func (a api) verify(ctx context.Context, o options) (bool, bool, error) {
	current, err := a.pull(ctx, sofaRepo, o.SofaPR)
	if err != nil {
		return false, false, err
	}
	if current.Head.Repo.FullName != sofaRepo || !sha40.MatchString(current.Head.SHA) || !sha40.MatchString(current.Base.SHA) {
		return false, false, errors.New("sofa PR identity invalid")
	}
	mainSHA, err := a.ref(ctx, "main")
	if err != nil {
		return false, false, err
	}
	if !o.AllowActive && current.State == "open" && current.Head.SHA == o.CandidateSHA && current.Base.SHA == o.PRBaseSHA && mainSHA == o.DisposableBaseSHA {
		return false, false, errors.New("current active sofa suite cannot be cleaned")
	}
	pr, err := a.pull(ctx, consumerRepo, o.DraftPR)
	if err != nil {
		return false, false, err
	}
	callerSHA, callerExists, err := a.optionalRef(ctx, o.caller())
	if err != nil || callerExists && callerSHA != o.CallerSHA || !callerExists && pr.State != "closed" {
		return false, false, errors.New("caller ref does not have exact expected head")
	}
	resultSHA, resultExists, err := a.optionalRef(ctx, o.result())
	if err != nil || resultExists && resultSHA != o.ResultSHA || !resultExists && (callerExists || pr.State != "closed") {
		return false, false, errors.New("result ref does not have exact expected head")
	}
	if callerExists {
		caller, err := a.commit(ctx, callerSHA)
		if err != nil {
			return false, false, err
		}
		if caller.Message != "Test sofa PR at exact candidate and base revisions" || len(caller.Parents) != 1 || caller.Parents[0].SHA != o.DisposableBaseSHA {
			return false, false, errors.New("caller commit is not suite-owned")
		}
		if err := a.singleChange(ctx, o.DisposableBaseSHA, callerSHA, workflowPath); err != nil {
			return false, false, err
		}
		workflow, err := a.content(ctx, workflowPath, callerSHA)
		if err != nil || string(workflow) != o.callerContent() {
			return false, false, errors.New("caller workflow is not exact suite content")
		}
	}
	if resultExists {
		result, err := a.commit(ctx, resultSHA)
		if err != nil {
			return false, false, err
		}
		marker := "sofa-e2e-suite=" + o.suite() + "; candidate=" + o.CandidateSHA + "; digest=" + o.CandidateDigest
		if result.Message != marker || len(result.Parents) != 1 || result.Parents[0].SHA != o.DisposableBaseSHA {
			return false, false, errors.New("result commit marker or parent differs")
		}
		if err := a.singleChange(ctx, o.DisposableBaseSHA, resultSHA, fixturePath); err != nil {
			return false, false, err
		}
		baseContent, err := a.content(ctx, fixturePath, o.DisposableBaseSHA)
		if err != nil {
			return false, false, err
		}
		wantContent, err := format.Source(baseContent)
		if err != nil || bytes.Equal(wantContent, baseContent) {
			return false, false, errors.New("fixture base is not a formatting canary")
		}
		resultContent, err := a.content(ctx, fixturePath, resultSHA)
		if err != nil || !bytes.Equal(resultContent, wantContent) {
			return false, false, errors.New("result fixture is not exact formatted content")
		}
	}
	if pr.State != "open" && pr.State != "closed" {
		return false, false, errors.New("draft PR state invalid")
	}
	if !ownedDraft(o, pr, resultExists) {
		return false, false, errors.New("draft PR ownership mismatch")
	}
	if resultExists {
		var linked []pull
		query := "/repos/" + consumerRepo + "/pulls?state=all&head=" + url.QueryEscape("kevinmartin:"+o.result()) + "&base=main&per_page=100"
		if err := a.get(ctx, query, &linked); err != nil || len(linked) != 1 || linked[0].Number != o.DraftPR {
			return false, false, errors.New("fixture branch PR ownership ambiguous")
		}
	}
	return callerExists, resultExists, nil
}

type refDeleter func(context.Context, string, string) error

func ownedDraft(o options, pr pull, resultExists bool) bool {
	wantBody := fmt.Sprintf("Trusted hosted gate result for sofa PR #%d. Suite `%s` at exact candidate `%s` and base `%s`; the only change is gofmt of fixture/greeting.go.\n\nThe candidate's report was revalidated by trusted disposable code before publication.", o.SofaPR, o.suite(), o.CandidateSHA, o.PRBaseSHA)
	return pr.Number == o.DraftPR && pr.Draft &&
		pr.Title == fmt.Sprintf("E2E fixture: format greeting for sofa PR #%d", o.SofaPR) &&
		pr.Body == wantBody &&
		pr.HTMLURL == fmt.Sprintf("https://github.com/%s/pull/%d", consumerRepo, o.DraftPR) &&
		pr.Head.Ref == o.result() &&
		pr.Head.SHA == o.ResultSHA && pr.Head.Repo.FullName == consumerRepo &&
		pr.Base.Ref == "main" && pr.Base.Repo.FullName == consumerRepo
}

func cleanup(ctx context.Context, a api, o options, deleteRef refDeleter) error {
	_, _, err := a.verify(ctx, o)
	if err != nil {
		return err
	}
	if !o.Apply {
		return nil
	}
	// Recheck everything immediately before the first write. Git's lease is the
	// atomic exact-head guard for each deletion; REST ref DELETE lacks a CAS.
	callerExists, resultExists, err := a.verify(ctx, o)
	if err != nil {
		return err
	}
	pr, err := a.pull(ctx, consumerRepo, o.DraftPR)
	if err != nil {
		return err
	}
	if !ownedDraft(o, pr, resultExists) {
		return errors.New("draft PR changed before closure")
	}
	if pr.State == "open" {
		var closed pull
		if err := a.patch(ctx, fmt.Sprintf("/repos/%s/pulls/%d", consumerRepo, o.DraftPR), map[string]string{"state": "closed"}, &closed); err != nil {
			return err
		}
		if closed.State != "closed" || !ownedDraft(o, closed, resultExists) {
			var restored pull
			if err := a.patch(ctx, fmt.Sprintf("/repos/%s/pulls/%d", consumerRepo, o.DraftPR), map[string]string{"state": "open"}, &restored); err != nil || restored.Number != o.DraftPR || restored.State != "open" {
				return errors.New("draft PR changed during closure and restoration failed")
			}
			return errors.New("draft PR changed during closure; original open state restored")
		}
	}
	// Caller first: if interrupted, the closed PR still anchors verification of
	// the result ref on a later manual retry.
	for _, item := range []struct {
		name, sha string
		exists    bool
	}{{o.caller(), o.CallerSHA, callerExists}, {o.result(), o.ResultSHA, resultExists}} {
		if !item.exists {
			continue
		}
		if _, _, err := a.verify(ctx, o); err != nil {
			return err
		}
		current, err := a.ref(ctx, item.name)
		if err != nil || current != item.sha {
			return errors.New("suite ref changed before exact-head deletion")
		}
		if err := deleteRef(ctx, item.name, item.sha); err != nil {
			return fmt.Errorf("exact-head deletion failed for %s: %w", item.name, err)
		}
	}
	return nil
}

// deleteWithLease uses Git protocol's compare-and-swap lease. A GitHub REST
// DELETE after a GET could erase a human update in the interval between them.
func deleteWithLease(token string) refDeleter {
	return func(ctx context.Context, branch, sha string) error {
		return leaseDelete(ctx, "https://github.com/"+consumerRepo+".git", token, branch, sha)
	}
}

func leaseDelete(ctx context.Context, remote, token, branch, sha string) error {
	if token == "" || !sha40.MatchString(sha) || !suiteBranch.MatchString(branch) {
		return errors.New("invalid lease input")
	}
	dir, err := os.MkdirTemp("", "sofa-gate-cleanup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	askpass := filepath.Join(dir, "askpass.sh")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\ncase \"$1\" in *Username*) printf '%s\\n' x-access-token;; *Password*) printf '%s\\n' \"$SOFA_PUBLISH_TOKEN\";; *) exit 1;; esac\n"), 0700); err != nil {
		return err
	}
	init := exec.CommandContext(ctx, "git", "init", "--bare", "--quiet", dir)
	init.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if err := init.Run(); err != nil {
		return errors.New("cannot initialize isolated cleanup repository")
	}
	cmd := exec.CommandContext(ctx, "git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "push", "--porcelain", "--force-with-lease=refs/heads/"+branch+":"+sha, remote, ":refs/heads/"+branch)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_ASKPASS="+askpass, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "SOFA_PUBLISH_TOKEN="+token)
	if err := cmd.Run(); err != nil {
		return errors.New("git push rejected exact ref lease")
	}
	return nil
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--success-report" {
		httpClient := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("GitHub redirect refused") }}
		a := api{client: httpClient, token: os.Getenv("GH_TOKEN"), writeToken: os.Getenv("SOFA_PUBLISH_TOKEN"), base: "https://api.github.com"}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := runSuccess(ctx, a, os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "sofa-gate-cleanup:", err)
			os.Exit(1)
		}
		return
	}
	o, err := parse(os.Args[1:])
	if err == nil && (os.Getenv("GITHUB_REPOSITORY") != consumerRepo || os.Getenv("GITHUB_REF") != "refs/heads/main" || os.Getenv("GH_TOKEN") == "" || (o.Apply && os.Getenv("SOFA_PUBLISH_TOKEN") == "")) {
		err = errors.New("trusted disposable default-branch identity or credential unavailable")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sofa-gate-cleanup:", err)
		os.Exit(1)
	}
	httpClient := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("GitHub redirect refused") }}
	a := api{client: httpClient, token: os.Getenv("GH_TOKEN"), writeToken: os.Getenv("SOFA_PUBLISH_TOKEN"), base: "https://api.github.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := cleanup(ctx, a, o, deleteWithLease(os.Getenv("SOFA_PUBLISH_TOKEN"))); err != nil {
		fmt.Fprintln(os.Stderr, "sofa-gate-cleanup:", err)
		os.Exit(1)
	}
	if o.Apply {
		fmt.Printf("closed disposable draft PR %d and removed exact suite refs %s, %s\n", o.DraftPR, o.caller(), o.result())
	} else {
		fmt.Printf("verified superseded suite %s; rerun with --apply to close PR and remove refs\n", o.suite())
	}
}
