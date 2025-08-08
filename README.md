# public-pinata

This project exposes a small REST API that enumerates public GitHub repositories
with a public bug bounty policy and, for repositories that opt in, scans their
GitHub Actions workflows for common security pitfalls such as
`pull_request_target` usage and event injections. A lightweight sandbox is used
to demonstrate exploitability with synthetic secrets.

## Running

The service expects a GitHub token and a comma separated list of repositories
that have opted in to scanning:

```bash
export GITHUB_TOKEN=ghp_...
export OPT_IN_REPOS="owner1/repo1,owner2/repo2"
go run .
```

It listens on port `8080` and provides three endpoints:

* `GET /healthz` – basic health check
* `GET /repos` – list popular repos with the `bug-bounty` topic
* `POST /scan/{owner}/{repo}` – scan a specific opted-in repository

The scanner also runs automatically every six hours to detect newly introduced
issues.

## Docker image

Build a container image using:

```bash
docker build -t public-pinata .
```
