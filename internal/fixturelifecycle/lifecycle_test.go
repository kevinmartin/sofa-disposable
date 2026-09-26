package fixturelifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, value any) *http.Response {
	b, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}
}

func TestReadyAndCleanupAreExactAndIdempotent(t *testing.T) {
	s := Suite{ID: "p2-" + strings.Repeat("a", 24), CandidateSHA: strings.Repeat("b", 40), PRBaseSHA: strings.Repeat("c", 40), DisposableBaseSHA: strings.Repeat("d", 40)}
	i := issue{Number: 41, NodeID: "I_41", State: "open", Title: s.title(), Body: s.body(), HTMLURL: "https://github.com/" + repo + "/issues/41"}
	created, added, ready, closed, archived := 0, 0, 0, 0, 0
	hasIssue, hasItem := false, false
	status := todoOptionID
	c := Client{Token: "project-token", IssueToken: "issue-token", BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		wantToken := "Bearer issue-token"
		if r.URL.Path == "/graphql" {
			wantToken = "Bearer project-token"
		}
		if r.Header.Get("Authorization") != wantToken {
			t.Fatal("wrong fixture credential")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/"+repo+"/issues":
			if !hasIssue {
				return response(200, []issue{}), nil
			}
			return response(200, []issue{i}), nil
		case r.Method == http.MethodPost && r.URL.Path == "/repos/"+repo+"/issues":
			created++
			hasIssue = true
			return response(201, i), nil
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/"+repo+"/issues/41":
			closed++
			i.State = "closed"
			return response(200, i), nil
		case r.Method == http.MethodPost && r.URL.Path == "/graphql":
			var request struct {
				Query string `json:"query"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			switch {
			case strings.Contains(request.Query, "addProjectV2ItemById"):
				added++
				hasItem = true
				return response(200, map[string]any{"data": map[string]any{"addProjectV2ItemById": map[string]any{"item": map[string]string{"id": "PVTI_41"}}}}), nil
			case strings.Contains(request.Query, "updateProjectV2ItemFieldValue"):
				ready++
				status = readyOptionID
				return response(200, map[string]any{"data": map[string]any{"updateProjectV2ItemFieldValue": map[string]any{"projectV2Item": map[string]string{"id": "PVTI_41"}}}}), nil
			case strings.Contains(request.Query, "archiveProjectV2Item"):
				archived++
				return response(200, map[string]any{"data": map[string]any{"archiveProjectV2Item": map[string]any{"item": map[string]any{"id": "PVTI_41", "isArchived": true}}}}), nil
			case strings.Contains(request.Query, "projectItems"):
				items := []any{}
				if hasItem {
					name := "Todo"
					if status == readyOptionID {
						name = "Ready"
					}
					items = append(items, map[string]any{"id": "PVTI_41", "isArchived": archived != 0, "project": map[string]string{"id": projectID}, "fieldValueByName": map[string]string{"optionId": status, "name": name}})
				}
				return response(200, map[string]any{"data": map[string]any{"node": map[string]any{"id": i.NodeID, "projectItems": map[string]any{"totalCount": len(items), "nodes": items}}}}), nil
			}
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		return nil, fmt.Errorf("unreachable")
	})}}
	ctx := context.Background()
	for n := 0; n < 2; n++ {
		resource, err := c.EnsureReady(ctx, s)
		if err != nil || resource.IssueNumber != 41 || resource.ProjectItem != "PVTI_41" || resource.Archived {
			t.Fatalf("ready %d: %+v %v", n, resource, err)
		}
	}
	for n := 0; n < 2; n++ {
		resource, err := c.Complete(ctx, s)
		if err != nil || !resource.Archived || !resource.Closed {
			t.Fatalf("cleanup %d: %+v %v", n, resource, err)
		}
	}
	if created != 1 || added != 1 || ready != 1 || closed != 1 || archived != 1 {
		t.Fatalf("duplicate mutation: create=%d add=%d ready=%d close=%d archive=%d", created, added, ready, closed, archived)
	}
	if _, err := c.EnsureReady(ctx, s); err == nil {
		t.Fatal("closed suite was reauthorized")
	}
}

func TestUntrustedOrAmbiguousIssueCannotBeReused(t *testing.T) {
	s := Suite{ID: "p2-" + strings.Repeat("a", 24), CandidateSHA: strings.Repeat("b", 40), PRBaseSHA: strings.Repeat("c", 40), DisposableBaseSHA: strings.Repeat("d", 40)}
	for _, tc := range []struct {
		name string
		list []issue
	}{
		{"changed body", []issue{{Number: 41, NodeID: "I_41", State: "open", Title: s.title(), Body: "untrusted", HTMLURL: "https://github.com/" + repo + "/issues/41"}}},
		{"ambiguous", []issue{{Number: 41, NodeID: "I_41", State: "open", Title: s.title(), Body: s.body(), HTMLURL: "https://github.com/" + repo + "/issues/41"}, {Number: 42, NodeID: "I_42", State: "open", Title: s.title(), Body: s.body(), HTMLURL: "https://github.com/" + repo + "/issues/42"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Client{Token: "project-token", IssueToken: "issue-token", BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet {
					t.Fatal("unexpected mutation")
				}
				return response(200, tc.list), nil
			})}}
			if _, err := c.EnsureReady(context.Background(), s); err == nil {
				t.Fatal("untrusted issue was accepted")
			}
		})
	}
}
