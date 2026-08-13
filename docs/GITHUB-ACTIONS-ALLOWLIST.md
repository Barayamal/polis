# GitHub Actions pinning and allowlist

Status: **HOLD — do not enable a restrictive repository Actions policy until
this change has passed review and CI.**

This baseline was prepared from `edge` commit
`424dcae02f0147723a19103dd2d971f6ec1b6db5`. Every external `uses:` reference
is fixed to a full 40-character commit SHA. The existing major versions are
preserved so supply-chain pinning is not mixed with action-version migrations.
The `tevko/sensemaking-tools` checkout is also fixed to commit
`988ad3547a9b5c3fe92fa6cd2bbff9837795fb6b`.

## Allowed actions

| Action | Purpose | Trust/maintenance note |
| --- | --- | --- |
| `actions/checkout` | source checkout | GitHub-owned |
| `actions/cache` | dependency cache | GitHub-owned |
| `actions/download-artifact` | CI artifact transfer | GitHub-owned |
| `actions/github-script` | coverage comment automation | GitHub-owned |
| `actions/setup-java` | Java runtime | GitHub-owned |
| `actions/setup-node` | Node.js runtime | GitHub-owned |
| `actions/setup-python` | Python runtime | GitHub-owned |
| `actions/upload-artifact` | CI artifact transfer | GitHub-owned |
| `aws-actions/amazon-ecr-login` | AWS ECR authentication | AWS-maintained; receives credentials |
| `aws-actions/configure-aws-credentials` | AWS OIDC/credential setup | AWS-maintained; privileged deployment action |
| `codecov/codecov-action` | coverage publication | External service; receives coverage data/token |
| `docker/setup-buildx-action` | Docker Buildx setup | Docker-maintained |
| `google-github-actions/auth` | Google Cloud authentication | Google-maintained; receives credentials |
| `DeLaGuardo/setup-clojure` | Clojure tooling | Community-maintained third party |
| `valitydev/action-download-file` | Sensemaker input download | Community-maintained third party; replace with `curl` |
| `exuanbo/actions-deploy-gist` | Sensemaker gist publication | Community-maintained third party; receives a gist token and should be replaced with `gh api` |

`.github/scripts/check-action-pins.mjs` enforces this exact action-name
allowlist and full-SHA references in the lint job. Any new action therefore
requires an intentional code and allowlist review.

## Repository-policy activation gate

Do not change the repository or organisation Actions policy as part of this
HOLD change. After the PR is approved and all workflows required by the target
branch pass:

1. Re-resolve every SHA against its upstream repository and record the intended
   release in the review.
2. Replace or separately approve the two community Sensemaker actions.
3. Upgrade retired action majors in separate compatibility PRs.
4. Keep the default token read-only and workflow PR approval disabled.
5. Change allowed actions from `all` to `selected`, allow only GitHub-owned and
   the reviewed publishers/actions above, and require full-SHA pinning.
6. Dispatch every manual/deployment workflow with synthetic or non-production
   inputs before treating the policy as complete.

Rollback is to restore `allowed_actions=all`; do not remove SHA pins merely to
make a workflow run.
