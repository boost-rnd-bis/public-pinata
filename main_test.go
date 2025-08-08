package main

import (
	"testing"
)

func TestAnalyzeWorkflow(t *testing.T) {
	yaml := []byte(`
on: pull_request_target
jobs:
  test:
    steps:
      - run: echo ${{ github.event }}
`)
	issues := AnalyzeWorkflow(yaml)
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}
}
