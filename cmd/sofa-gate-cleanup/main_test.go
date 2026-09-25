package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/format"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testOptions() options {
	return options{SofaPR: 2, CandidateSHA: strings.Repeat("a", 40), PRBaseSHA: strings.Repeat("b", 40), DisposableBaseSHA: strings.Repeat("c", 40), CallerSHA: strings.Repeat("d", 40), ResultSHA: strings.Repeat("e", 40), CandidateDigest: strings.Repeat("f", 64), DraftPR: 39}
}

func jsonReply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testAPI(t *testing.T, o options, active, badCaller, badResult, missingCaller bool) (api, *[]string) {
	t.Helper()
	calls := []string{}
	baseTree, callerTree, resultTree := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	baseBlob, newBlob := strings.Repeat("4", 40), strings.Repeat("5", 40)
	callerBlob := strings.Repeat("6", 40)
	wantBody := fmt.Sprintf("Trusted hosted gate result for sofa PR #%d. Suite `%s` at exact candidate `%s` and base `%s`; the only change is gofmt of fixture/greeting.go.\n\nThe candidate's report was revalidated by trusted disposable code before publication.", o.SofaPR, o.suite(), o.CandidateSHA, o.PRBaseSHA)
	pr := pull{Number: o.DraftPR, State: "open", Draft: true, Title: fmt.Sprintf("E2E fixture: format greeting for sofa PR #%d", o.SofaPR), Body: wantBody, HTMLURL: fmt.Sprintf("https://github.com/%s/pull/%d", consumerRepo, o.DraftPR)}
	if missingCaller {
		pr.State = "closed"
	}
	pr.Head.Ref, pr.Head.SHA, pr.Head.Repo.FullName = o.result(), o.ResultSHA, consumerRepo
	pr.Base.Ref, pr.Base.Repo.FullName = "main", consumerRepo
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && path == fmt.Sprintf("/repos/%s/pulls/%d", sofaRepo, o.SofaPR):
			p := pull{Number: o.SofaPR, State: "open"}
			p.Head.Repo.FullName = sofaRepo
			p.Head.SHA, p.Base.SHA = strings.Repeat("9", 40), o.PRBaseSHA
			if active {
				p.Head.SHA = o.CandidateSHA
			}
			jsonReply(w, p)
		case r.Method == http.MethodGet && path == "/repos/"+consumerRepo+"/git/ref/heads/main":
			main := strings.Repeat("8", 40)
			if active {
				main = o.DisposableBaseSHA
			}
			jsonReply(w, map[string]any{"object": map[string]string{"sha": main}})
		case r.Method == http.MethodGet && path == "/repos/"+consumerRepo+"/git/ref/heads/"+o.caller():
			if missingCaller {
				http.Error(w, "missing", http.StatusNotFound)
				return
			}
			jsonReply(w, map[string]any{"object": map[string]string{"sha": o.CallerSHA}})
		case r.Method == http.MethodGet && path == "/repos/"+consumerRepo+"/git/ref/heads/"+o.result():
			jsonReply(w, map[string]any{"object": map[string]string{"sha": o.ResultSHA}})
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/repos/"+consumerRepo+"/git/commits/"):
			sha := strings.TrimPrefix(path, "/repos/"+consumerRepo+"/git/commits/")
			message, tree, parents := "base", baseTree, []any{}
			if sha == o.CallerSHA {
				message, tree, parents = "Test sofa PR at exact candidate and base revisions", callerTree, []any{map[string]string{"sha": o.DisposableBaseSHA}}
			}
			if sha == o.ResultSHA {
				message, tree, parents = "sofa-e2e-suite="+o.suite()+"; candidate="+o.CandidateSHA+"; digest="+o.CandidateDigest, resultTree, []any{map[string]string{"sha": o.DisposableBaseSHA}}
				if badResult {
					message = "human result"
				}
			}
			jsonReply(w, map[string]any{"sha": sha, "message": message, "tree": map[string]string{"sha": tree}, "parents": parents})
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/repos/"+consumerRepo+"/git/trees/"):
			sha := strings.TrimPrefix(path, "/repos/"+consumerRepo+"/git/trees/")
			entries := []treeEntry{{Path: workflowPath, Mode: "100644", Type: "blob", SHA: baseBlob}, {Path: fixturePath, Mode: "100644", Type: "blob", SHA: baseBlob}}
			if sha == callerTree {
				entries[0].SHA = callerBlob
			}
			if sha == resultTree {
				entries[1].SHA = newBlob
			}
			jsonReply(w, map[string]any{"tree": entries, "truncated": false})
		case r.Method == http.MethodGet && path == "/repos/"+consumerRepo+"/contents/"+workflowPath:
			content := o.callerContent()
			if badCaller {
				content += "# human edit\n"
			}
			jsonReply(w, map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(content))})
		case r.Method == http.MethodGet && path == "/repos/"+consumerRepo+"/contents/"+fixturePath:
			content := []byte("package fixture\nfunc Greeting()string{return \"hi\"}\n")
			if r.URL.Query().Get("ref") == o.ResultSHA {
				content, _ = format.Source(content)
			}
			jsonReply(w, map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString(content)})
		case r.Method == http.MethodGet && path == fmt.Sprintf("/repos/%s/pulls/%d", consumerRepo, o.DraftPR):
			jsonReply(w, pr)
		case r.Method == http.MethodGet && path == "/repos/"+consumerRepo+"/pulls":
			jsonReply(w, []pull{pr})
		case r.Method == http.MethodPatch && path == fmt.Sprintf("/repos/%s/pulls/%d", consumerRepo, o.DraftPR):
			if r.Header.Get("Authorization") != "Bearer test-write" {
				http.Error(w, "wrong token", http.StatusForbidden)
				return
			}
			pr.State = "closed"
			jsonReply(w, pr)
		default:
			http.Error(w, "unhandled", http.StatusNotFound)
		}
	})
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Result(), nil
	})}
	return api{client: client, token: "test", writeToken: "test-write", base: "https://api.github.com"}, &calls
}

func TestCleanupRejectsActiveOrChangedSuiteBeforeWrite(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		active, badCaller, badResult bool
	}{{"active", true, false, false}, {"changed workflow", false, true, false}, {"changed result marker", false, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			o := testOptions()
			o.Apply = true
			a, calls := testAPI(t, o, tc.active, tc.badCaller, tc.badResult, false)
			deleted := false
			if err := cleanup(context.Background(), a, o, func(context.Context, string, string) error { deleted = true; return nil }); err == nil {
				t.Fatal("accepted active or changed suite")
			}
			if deleted {
				t.Fatal("deleted ref")
			}
			for _, call := range *calls {
				if strings.HasPrefix(call, "PATCH ") {
					t.Fatal("closed PR before ownership verification")
				}
			}
		})
	}
}

func TestCleanupClosesThenDeletesOnlyExactOwnedRefs(t *testing.T) {
	o := testOptions()
	o.Apply = true
	a, calls := testAPI(t, o, false, false, false, false)
	var deleted []string
	if err := cleanup(context.Background(), a, o, func(_ context.Context, branch, sha string) error {
		deleted = append(deleted, branch+":"+sha)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 || deleted[0] != o.caller()+":"+o.CallerSHA || deleted[1] != o.result()+":"+o.ResultSHA {
		t.Fatalf("unexpected deletion: %v", deleted)
	}
	closed := false
	for _, call := range *calls {
		if strings.HasPrefix(call, "PATCH ") {
			closed = true
		}
	}
	if !closed {
		t.Fatal("draft PR was not closed")
	}
}

func TestCleanupResumesAfterCallerDeleted(t *testing.T) {
	o := testOptions()
	o.Apply = true
	a, _ := testAPI(t, o, false, false, false, true)
	var deleted []string
	if err := cleanup(context.Background(), a, o, func(_ context.Context, branch, sha string) error {
		deleted = append(deleted, branch+":"+sha)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != o.result()+":"+o.ResultSHA {
		t.Fatalf("unexpected retry deletion: %v", deleted)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestLeaseDeleteRejectsMovedHeadAndHumanBranch(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "--bare", remote)
	runGit(t, work, "init")
	runGit(t, work, "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "one")
	first := runGit(t, work, "rev-parse", "HEAD")
	branch := testOptions().caller()
	runGit(t, work, "push", remote, "HEAD:refs/heads/"+branch)
	runGit(t, work, "-c", "commit.gpgsign=false", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "two")
	second := runGit(t, work, "rev-parse", "HEAD")
	runGit(t, work, "push", remote, "HEAD:refs/heads/"+branch)
	if err := leaseDelete(context.Background(), remote, "dummy", branch, first); err == nil {
		t.Fatal("deleted moved ref despite stale lease")
	}
	if got := runGit(t, root, "--git-dir", remote, "rev-parse", "refs/heads/"+branch); got != second {
		t.Fatal("stale lease changed ref")
	}
	if err := leaseDelete(context.Background(), remote, "dummy", "human/topic", second); err == nil {
		t.Fatal("accepted human branch")
	}
	if err := leaseDelete(context.Background(), remote, "dummy", branch, second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(remote); err != nil {
		t.Fatal(err)
	}
}
