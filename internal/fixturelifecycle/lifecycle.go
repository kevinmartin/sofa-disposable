// Package fixturelifecycle owns disposable-only issue and Project resources
// for one exact hosted gate suite. It never reads candidate artifacts or prose.
package fixturelifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	repo          = "kevinmartin/sofa-disposable"
	projectID     = "PVT_kwHOAAfL7c4Bke1I"
	statusFieldID = "PVTSSF_lAHOAAfL7c4Bke1IzhjPQ38"
	readyOptionID = "e4557284"
	todoOptionID  = "f75ad846"
)

var suitePattern = regexp.MustCompile(`^p[1-9][0-9]*-[0-9a-f]{24}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Suite struct {
	ID, CandidateSHA, PRBaseSHA, DisposableBaseSHA string
}

func (s Suite) valid() bool {
	return suitePattern.MatchString(s.ID) && shaPattern.MatchString(s.CandidateSHA) && shaPattern.MatchString(s.PRBaseSHA) && shaPattern.MatchString(s.DisposableBaseSHA)
}

func (s Suite) title() string { return "Hosted E2E " + s.ID }
func (s Suite) body() string {
	return fmt.Sprintf("Trusted disposable test item for suite `%s`.\n\nSofa candidate: `%s`\nSofa PR base: `%s`\nDisposable base: `%s`\n\nThis item is created and moved to Ready by the trusted disposable coordinator. It is not a production work request.\n", s.ID, s.CandidateSHA, s.PRBaseSHA, s.DisposableBaseSHA)
}

type Resource struct {
	IssueNumber int
	IssueURL    string
	ProjectItem string
	Archived    bool
	Closed      bool
}

type Client struct {
	HTTP    *http.Client
	Token   string
	BaseURL string // Empty uses GitHub. Tests may supply a local fake transport.
}

type issue struct {
	Number  int       `json:"number"`
	NodeID  string    `json:"node_id"`
	State   string    `json:"state"`
	Title   string    `json:"title"`
	Body    string    `json:"body"`
	HTMLURL string    `json:"html_url"`
	Pull    *struct{} `json:"pull_request"`
}

func (c Client) call(ctx context.Context, method, path string, input, output any) error {
	if c.Token == "" || c.HTTP == nil || (!strings.HasPrefix(path, "/repos/"+repo+"/") && path != "/graphql") || strings.ContainsAny(path, "\r\n#") {
		return errors.New("fixture lifecycle credential or request unavailable")
	}
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	base := c.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "sofa-disposable-fixture-lifecycle")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("fixture lifecycle transport unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fixture lifecycle API returned HTTP %d", resp.StatusCode)
	}
	if output == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(output)
}

func (c Client) graphql(ctx context.Context, query string, vars any, output any) error {
	var envelope struct {
		Data   json.RawMessage   `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := c.call(ctx, http.MethodPost, "/graphql", map[string]any{"query": query, "variables": vars}, &envelope); err != nil {
		return err
	}
	if len(envelope.Errors) != 0 || len(envelope.Data) == 0 {
		return errors.New("fixture Project query or mutation failed")
	}
	if err := json.Unmarshal(envelope.Data, output); err != nil {
		return errors.New("fixture Project response invalid")
	}
	return nil
}

func validIssue(i issue, s Suite) bool {
	return i.Number > 0 && i.NodeID != "" && i.Pull == nil && i.Title == s.title() && i.Body == s.body() &&
		i.HTMLURL == fmt.Sprintf("https://github.com/%s/issues/%d", repo, i.Number) && (i.State == "open" || i.State == "closed")
}

// findIssue scans a bounded issue history. At the bound, it fails closed
// instead of creating a duplicate after a lost create response.
func (c Client) findIssue(ctx context.Context, s Suite) (issue, bool, error) {
	var found issue
	for page := 1; page <= 10; page++ {
		var list []issue
		path := fmt.Sprintf("/repos/%s/issues?state=all&sort=created&direction=desc&per_page=100&page=%d", repo, page)
		if err := c.call(ctx, http.MethodGet, path, nil, &list); err != nil {
			return issue{}, false, err
		}
		if len(list) > 100 {
			return issue{}, false, errors.New("fixture issue page invalid")
		}
		for _, i := range list {
			if i.Title != s.title() {
				continue
			}
			if !validIssue(i, s) || found.Number != 0 {
				return issue{}, false, errors.New("suite issue is ambiguous or changed")
			}
			found = i
		}
		if len(list) < 100 {
			return found, found.Number != 0, nil
		}
	}
	return issue{}, false, errors.New("fixture issue history exceeds bounded scan")
}

type projectItem struct {
	ID         string `json:"id"`
	IsArchived bool   `json:"isArchived"`
	Project    struct {
		ID string `json:"id"`
	} `json:"project"`
	Status struct {
		OptionID string `json:"optionId"`
		Name     string `json:"name"`
	} `json:"fieldValueByName"`
}

const issueProjectQuery = `query($id:ID!){node(id:$id){... on Issue{id projectItems(first:100,includeArchived:true){totalCount nodes{id isArchived project{id} fieldValueByName(name:"Status"){... on ProjectV2ItemFieldSingleSelectValue{optionId name}}}}}}}`

func (c Client) item(ctx context.Context, i issue) (projectItem, bool, error) {
	var out struct {
		Node struct {
			ID           string `json:"id"`
			ProjectItems struct {
				TotalCount int           `json:"totalCount"`
				Nodes      []projectItem `json:"nodes"`
			} `json:"projectItems"`
		} `json:"node"`
	}
	if err := c.graphql(ctx, issueProjectQuery, map[string]string{"id": i.NodeID}, &out); err != nil {
		return projectItem{}, false, err
	}
	if out.Node.ID != i.NodeID || out.Node.ProjectItems.TotalCount < 0 || out.Node.ProjectItems.TotalCount > 100 || len(out.Node.ProjectItems.Nodes) != out.Node.ProjectItems.TotalCount {
		return projectItem{}, false, errors.New("suite issue Project listing invalid")
	}
	var found projectItem
	for _, item := range out.Node.ProjectItems.Nodes {
		if item.Project.ID != projectID {
			continue
		}
		if item.ID == "" || found.ID != "" {
			return projectItem{}, false, errors.New("suite Project item ambiguous")
		}
		found = item
	}
	return found, found.ID != "", nil
}

func (c Client) createIssue(ctx context.Context, s Suite) (issue, error) {
	var made issue
	err := c.call(ctx, http.MethodPost, "/repos/"+repo+"/issues", map[string]string{"title": s.title(), "body": s.body()}, &made)
	if err == nil && validIssue(made, s) && made.State == "open" {
		return made, nil
	}
	// A successful create with a lost response must not create a second issue.
	if existing, ok, lookupErr := c.findIssue(ctx, s); lookupErr == nil && ok {
		return existing, nil
	}
	return issue{}, errors.New("suite issue creation could not be reconciled")
}

func (c Client) addItem(ctx context.Context, i issue) error {
	const mutation = `mutation($project:ID!,$content:ID!){addProjectV2ItemById(input:{projectId:$project,contentId:$content}){item{id}}}`
	var out struct {
		Add struct {
			Item struct {
				ID string `json:"id"`
			} `json:"item"`
		} `json:"addProjectV2ItemById"`
	}
	err := c.graphql(ctx, mutation, map[string]string{"project": projectID, "content": i.NodeID}, &out)
	if err == nil && out.Add.Item.ID != "" {
		return nil
	}
	if item, ok, lookupErr := c.item(ctx, i); lookupErr == nil && ok && item.ID != "" {
		return nil
	}
	return errors.New("suite Project item creation could not be reconciled")
}

func (c Client) setReady(ctx context.Context, id string) error {
	const mutation = `mutation($project:ID!,$item:ID!,$field:ID!,$option:String!){updateProjectV2ItemFieldValue(input:{projectId:$project,itemId:$item,fieldId:$field,value:{singleSelectOptionId:$option}}){projectV2Item{id}}}`
	var out struct {
		Update struct {
			Item struct {
				ID string `json:"id"`
			} `json:"projectV2Item"`
		} `json:"updateProjectV2ItemFieldValue"`
	}
	if err := c.graphql(ctx, mutation, map[string]string{"project": projectID, "item": id, "field": statusFieldID, "option": readyOptionID}, &out); err != nil {
		return err
	}
	if out.Update.Item.ID != id {
		return errors.New("suite Project Ready mutation identity mismatch")
	}
	return nil
}

func (c Client) resource(ctx context.Context, s Suite) (issue, projectItem, error) {
	if !s.valid() {
		return issue{}, projectItem{}, errors.New("invalid exact hosted suite")
	}
	i, ok, err := c.findIssue(ctx, s)
	if err != nil {
		return issue{}, projectItem{}, err
	}
	if !ok {
		return issue{}, projectItem{}, errors.New("suite issue unavailable")
	}
	item, ok, err := c.item(ctx, i)
	if err != nil {
		return issue{}, projectItem{}, err
	}
	if !ok {
		return issue{}, projectItem{}, errors.New("suite Project item unavailable")
	}
	return i, item, nil
}

func makeResource(i issue, p projectItem) Resource {
	return Resource{i.Number, i.HTMLURL, p.ID, p.IsArchived, i.State == "closed"}
}

// EnsureReady creates one exact issue and moves its Project item to Ready.
// It will not reopen a completed item or override a human status change.
func (c Client) EnsureReady(ctx context.Context, s Suite) (Resource, error) {
	if !s.valid() {
		return Resource{}, errors.New("invalid exact hosted suite")
	}
	i, ok, err := c.findIssue(ctx, s)
	if err != nil {
		return Resource{}, err
	}
	if !ok {
		i, err = c.createIssue(ctx, s)
		if err != nil {
			return Resource{}, err
		}
	}
	if i.State != "open" {
		return Resource{}, errors.New("suite issue is closed before dispatch")
	}
	item, ok, err := c.item(ctx, i)
	if err != nil {
		return Resource{}, err
	}
	if !ok {
		if err := c.addItem(ctx, i); err != nil {
			return Resource{}, err
		}
		item, ok, err = c.item(ctx, i)
		if err != nil || !ok {
			return Resource{}, errors.New("created suite Project item unavailable")
		}
	}
	if item.IsArchived {
		return Resource{}, errors.New("suite Project item archived before dispatch")
	}
	if item.Status.OptionID != readyOptionID || item.Status.Name != "Ready" {
		if item.Status.OptionID != "" && (item.Status.OptionID != todoOptionID || item.Status.Name != "Todo") {
			return Resource{}, errors.New("suite Project status changed unexpectedly")
		}
		if err := c.setReady(ctx, item.ID); err != nil {
			return Resource{}, err
		}
		item, ok, err = c.item(ctx, i)
		if err != nil || !ok {
			return Resource{}, errors.New("suite Project Ready transition unavailable")
		}
	}
	if item.IsArchived || item.Status.OptionID != readyOptionID || item.Status.Name != "Ready" {
		return Resource{}, errors.New("suite Project item not Ready")
	}
	return makeResource(i, item), nil
}

// Verify accepts Ready or an already completed resource to make observer
// retries safe after status publication or a partially successful cleanup.
func (c Client) Verify(ctx context.Context, s Suite) (Resource, error) {
	i, item, err := c.resource(ctx, s)
	if err != nil {
		return Resource{}, err
	}
	if item.Status.OptionID != readyOptionID || item.Status.Name != "Ready" {
		return Resource{}, errors.New("suite Project item was not Ready")
	}
	if item.IsArchived != (i.State == "closed") {
		return Resource{}, errors.New("suite issue and Project closure disagree")
	}
	return makeResource(i, item), nil
}

// Complete closes only the exact owned issue and archives its Project item.
// A retry can finish either step after a lost response without touching other
// issues or Project items.
func (c Client) Complete(ctx context.Context, s Suite) (Resource, error) {
	i, item, err := c.resource(ctx, s)
	if err != nil {
		return Resource{}, err
	}
	if item.Status.OptionID != readyOptionID || item.Status.Name != "Ready" || (item.IsArchived && i.State != "closed") {
		return Resource{}, errors.New("suite Project item changed before cleanup")
	}
	if i.State == "open" {
		var closed issue
		err = c.call(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/%d", repo, i.Number), map[string]string{"state": "closed"}, &closed)
		if err != nil || !validIssue(closed, s) || closed.State != "closed" {
			return Resource{}, errors.New("suite issue close could not be verified")
		}
	}
	if !item.IsArchived {
		const mutation = `mutation($project:ID!,$item:ID!){archiveProjectV2Item(input:{projectId:$project,itemId:$item}){item{id isArchived}}}`
		var out struct {
			Archive struct {
				Item struct {
					ID       string `json:"id"`
					Archived bool   `json:"isArchived"`
				} `json:"item"`
			} `json:"archiveProjectV2Item"`
		}
		if err := c.graphql(ctx, mutation, map[string]string{"project": projectID, "item": item.ID}, &out); err != nil {
			if latest, found, readErr := c.item(ctx, i); readErr != nil || !found || !latest.IsArchived {
				return Resource{}, errors.New("suite Project archive could not be reconciled")
			}
		} else if out.Archive.Item.ID != item.ID || !out.Archive.Item.Archived {
			return Resource{}, errors.New("suite Project archive identity mismatch")
		}
	}
	i, item, err = c.resource(ctx, s)
	if err != nil || i.State != "closed" || !item.IsArchived {
		return Resource{}, errors.New("suite issue/Project cleanup incomplete")
	}
	return makeResource(i, item), nil
}

func ProjectURL() string { return "https://github.com/users/kevinmartin/projects/2" }
func ProjectID() string  { return projectID }
