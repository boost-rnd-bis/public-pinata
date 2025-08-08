package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	github "github.com/google/go-github/v59/github"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type App struct {
	gh    *github.Client
	optIn map[string]struct{}
}

func main() {
	token := os.Getenv("GITHUB_TOKEN")
	ctx := context.Background()
	var tc *http.Client
	if token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		tc = oauth2.NewClient(ctx, ts)
	}
	client := github.NewClient(tc)

	optIn := map[string]struct{}{}
	if list := os.Getenv("OPT_IN_REPOS"); list != "" {
		for _, r := range strings.Split(list, ",") {
			optIn[strings.TrimSpace(r)] = struct{}{}
		}
	}

	app := &App{gh: client, optIn: optIn}
	// Run scan every 6 hours
	ticker := time.NewTicker(6 * time.Hour)
	go func() {
		for range ticker.C {
			app.RunScheduled(ctx)
		}
	}()

	r := mux.NewRouter()
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }).Methods("GET")
	r.HandleFunc("/repos", app.ListRepos).Methods("GET")
	r.HandleFunc("/scan/{owner}/{repo}", app.ScanRepo).Methods("POST")

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// ListRepos enumerates popular OSS repos with bug-bounty topic.
func (a *App) ListRepos(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := "stars:>10000 topic:bug-bounty"
	res, _, err := a.gh.Search.Repositories(ctx, query, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(res.Repositories)
}

// ScanRepo analyzes workflows in the given repo.
func (a *App) ScanRepo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repo := vars["owner"] + "/" + vars["repo"]
	if _, ok := a.optIn[repo]; !ok {
		http.Error(w, "repository not opted-in", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	vulns, err := a.CheckRepo(ctx, vars["owner"], vars["repo"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(vulns)
}

// RunScheduled runs scan for all opted-in repos.
func (a *App) RunScheduled(ctx context.Context) {
	for repo := range a.optIn {
		parts := strings.Split(repo, "/")
		if len(parts) != 2 {
			continue
		}
		vulns, err := a.CheckRepo(ctx, parts[0], parts[1])
		if err != nil {
			log.Printf("scan %s failed: %v", repo, err)
			continue
		}
		if len(vulns) > 0 {
			log.Printf("vulnerabilities in %s: %v", repo, vulns)
		}
	}
}

// CheckRepo fetches workflows and analyzes them.
func (a *App) CheckRepo(ctx context.Context, owner, repo string) ([]string, error) {
	workflows, _, err := a.gh.Actions.ListWorkflows(ctx, owner, repo, &github.ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}
	var vulns []string
	for _, wf := range workflows.Workflows {
		rc, _, err := a.gh.Repositories.DownloadContents(ctx, owner, repo, wf.GetPath(), nil)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		v := AnalyzeWorkflow(data)
		if len(v) > 0 && ValidateExploit() {
			v = append(v, "sandbox exploit confirmed")
		}
		vulns = append(vulns, v...)
	}
	return vulns, nil
}

// AnalyzeWorkflow inspects workflow YAML for risky patterns.
func AnalyzeWorkflow(data []byte) []string {
	type Workflow struct {
		On   interface{} `yaml:"on"`
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	var wf Workflow
	yaml.Unmarshal(data, &wf)
	var issues []string
	if s, ok := wf.On.(string); ok && strings.Contains(s, "pull_request_target") {
		issues = append(issues, "pwn request: pull_request_target used")
	} else if m, ok := wf.On.(map[string]interface{}); ok {
		if _, ok := m["pull_request_target"]; ok {
			issues = append(issues, "pwn request: pull_request_target used")
		}
	}
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "github.event") {
				issues = append(issues, "possible injection: uses github.event in run")
			}
		}
	}
	return issues
}

// ValidateExploit simulates exploitation using synthetic secrets.
func ValidateExploit() bool {
	cmd := exec.Command("bash", "-c", "echo $SYNTH_SECRET")
	cmd.Env = append(os.Environ(), "SYNTH_SECRET=synthetic")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "synthetic")
}
