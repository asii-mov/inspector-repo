# Security Inspector

A GitHub Action for security teams dealing with more pull requests than they can review, now that
AI writes more of the code. The security team lists the components they care about. The inspector
flags every pull request that touches one of them and blocks merge until the security team has
reviewed it. Everything else, like UI tweaks, copy changes and styling, merges without waiting on security.

It doesn't try to decide whether a change is dangerous. It watches **components**, and **any**
change to a watched component is flagged: a refactor of the login code gets the same review as a
change to its password check.

- **You decide what's critical.** A rule describes a component by where it lives
  ("anything under `auth/`") and/or what its files contain ("any file that imports `passport`
  or defines `login()`"), so auth code outside the auth folder is covered too.
- **Conditions.** Rules, or the whole policy, can be limited to certain pull requests, e.g. only
  PRs into `main` or `release/*`.
- **Priority repositories.** Mark sensitive repositories (PCI, identity, …) for stricter treatment:
  a lower severity threshold, severity boosts, more approvals, no bypass, extra rules.
- **Clear reports.** A single pull request comment lists each flagged component, why it matters,
  what reviewers should check, the files and line counts, and the actual diff lines that triggered it.
- **Merge gate.** A `Security Inspector` commit status turns green when nothing critical changed,
  when the security team approves, or after an authorised bypass.
- **Bypass for false positives.** Authorised people comment `/security-bypass <justification>`.
  The bypass is recorded on the PR as an audit trail. It stops applying if the flagged files
  change, and deleting the command comment revokes it.

```
 pull request opened / updated / reviewed / commented
                      │
                      ▼
  ┌─────────────────────────────────────────────────┐
  │ load policy (central repo + base-branch rules)  │
  │ list changed files and diff hunks via the API   │
  │ match rules → findings (with priority boosts)   │
  │ read security approvals and recorded bypasses   │
  └─────────────────────────────────────────────────┘
                      │
      ┌───────────────┼──────────────────┬───────────────────┐
      ▼               ▼                  ▼                   ▼
    clear          blocked            approved            bypassed
  ✅ status     ❌ status + report   ✅ status + label    ✅ status + label
                + label + review
                  request
```

## Quick start

### 1. Write the policy (security team)

Create a repository the security team controls, e.g. `acme/security-policies`, and add
`security-inspector-policy.yml`. Start from [`examples/security-inspector-policy.yml`](examples/security-inspector-policy.yml),
which covers authentication, authorisation, sessions/CSRF, cryptography/TLS, secrets management,
security headers/CORS, payments, infrastructure/IAM, CI pipelines and dependencies.

```yaml
version: 1
settings:
  blockOn: high                     # findings at/above this severity need security review
  securityTeam: { teams: [acme/security] }
  bypass: { teams: [acme/engineering-leads], minReasonLength: 15 }
  when: { baseBranches: [main, "release/*"] }   # only PRs into these branches are inspected

priorityRepositories:
  - name: payments
    reason: PCI-DSS cardholder data environment
    repositories: ["acme/payments-*", "acme/billing-api"]
    blockOn: medium
    requiredApprovals: 2
    allowBypass: false

rules:
  - id: authentication
    name: Authentication
    severity: critical
    description: Login, credential verification and token issuance decide who a user is.
    guidance: Review every change, including refactors.
    match: any                      # a matching path OR file content is enough
    paths: ["**/auth/**", "**/*login*"]
    excludePaths: ["**/*.test.*", "**/*.css"]
    fileContent:                    # ANY change to a file containing one of these is flagged
      - '(from|require\()\s*["''](passport|jsonwebtoken|bcrypt|argon2)["'']'
      - '\b(function|def)\s+\w*([Ll]ogin|[Aa]uthenticate|verify_?[Pp]assword)\w*\s*\('
```

Check it before committing:

```sh
npx github:asii-mov/inspector-repo validate security-inspector-policy.yml
```

### 2. Add the workflow to each repository

Copy [`examples/workflows/security-inspector.yml`](examples/workflows/security-inspector.yml) to
`.github/workflows/security-inspector.yml`:

```yaml
on:
  pull_request_target: { types: [opened, synchronize, reopened, ready_for_review, edited] }
  pull_request_review: { types: [submitted, dismissed] }
  issue_comment: { types: [created] }

permissions: { contents: read, pull-requests: write, issues: write, statuses: write }

jobs:
  inspect:
    if: >-
      (github.event_name != 'issue_comment' || github.event.issue.pull_request) &&
      (github.event.action != 'edited' || github.event.changes.base)
    runs-on: ubuntu-latest
    steps:
      - uses: asii-mov/inspector-repo@v1
        with:
          org-token: ${{ steps.app-token.outputs.token }}   # see "Tokens" below
          policy-repository: acme/security-policies
```

### 3. Make it required

Mark the **`Security Inspector`** status as required, either in each repository's branch protection or
once for the whole organisation with a ruleset (*Organization settings → Rules → Rulesets →
Require status checks to pass*). A blocked pull request can't be merged until the status turns
green.

## How decisions are made

| State | When | Status |
|---|---|---|
| `skipped` | The pull request doesn't meet `settings.when` (e.g. it targets `dev`) | ✅ success ("Not applicable") |
| `clear` | No finding at or above `blockOn` (after priority boosts) | ✅ success |
| `approved` | Enough security reviewers approved, none requested changes, and no flagged file changed since | ✅ success |
| `bypassed` | An authorised user ran the bypass command and the flagged changes are the same as when they did | ✅ success |
| `blocked` | Anything else | ❌ failure (or `pending`, see `blocked-state`) |

- **Approvals** count when the reviewer is on `settings.securityTeam` and isn't the author. An approval
  still counts after new commits as long as none of those commits touch a flagged file
  (`staleApprovals: flagged-changes`). Set `staleApprovals: any-change` to require re-approval after every push.
- **Changes requested** by a security reviewer always blocks, even over a bypass.
- **Bypass** (`/security-bypass <justification>`):
  - allowed for the security team plus `settings.bypass.teams`/`users`. The author can't bypass their
    own PR unless `allowAuthor: true`
  - needs a justification of at least `minReasonLength` characters
  - disabled in priority repositories with `allowBypass: false`
  - the inspector replies with an audit comment naming who bypassed it, why, at which commit and
    which components it covered
  - stops applying when a flagged file changes or a new flagged file appears
  - revoked by deleting the command comment
- **`/security-recheck`** re-runs the evaluation. Use it if a review on a fork PR didn't update the
  status (GitHub gives `pull_request_review` runs from forks a read-only token).

## Policy reference

### Rules

| Field | Default | Description |
|---|---|---|
| `id` | *required* | Stable identifier (letters, digits, `.`, `_`, `-`). |
| `name` | *required* | Component name shown to developers, e.g. "Authentication". |
| `description` | | Why it's security critical. |
| `guidance` | | What the reviewer should check. |
| `severity` | `high` | `low`, `medium`, `high` or `critical`. |
| `paths` | `[]` | Glob patterns ([picomatch](https://github.com/micromatch/picomatch)) matched case-insensitively against the file path; renames also match the old path. Any change to a matching file is flagged. |
| `fileContent` | `[]` | Regular expressions matched against the **whole file**. If one matches, the file is part of the component and **any** change to it is flagged, even if the changed lines look harmless. A change that removes the marker also counts. `^`/`$` anchor to lines. |
| `excludePaths` | `[]` | Globs excluded from this rule (tests, docs, styles…). |
| `content` | `[]` | Regular expressions matched against the **changed lines** only, to catch specific edits anywhere in the codebase. Either a string or `{ pattern, flags }` (as are `fileContent` entries). |
| `contentScope` | `both` | Which changed lines `content` checks: `added`, `removed`, or `both`. |
| `match` | `all` | When more than one of `paths`, `fileContent` and `content` is set: `all` needs every one to match, `any` needs one. For "any change to this component", use `any`. |
| `when` | | Pull request conditions, see below. |
| `repositories` / `excludeRepositories` | `[]` | Limit the rule to (or exclude) `owner/repo` globs. |
| `priorityOnly` | `false` | Only apply in priority repositories. |

A rule needs at least one of `paths`, `fileContent` or `content`.

`fileContent` reads each changed file at the PR's head commit (one API call per file, up to
`settings.fileContentLimit`, files up to 1 MB). Deleted files are checked through the diff,
without an extra read. Files that can't be read are listed in the report. When a `match: all`
rule can't check a file's content but its other criteria match, the file is still flagged.

### Conditions (`when`)

`when` can be set on a rule, or under `settings` for the whole policy. Each list takes branch
globs, and an empty list means no restriction.

```yaml
when:
  baseBranches: [main, "release/*"]        # PRs merging into these branches
  excludeBaseBranches: []
  headBranches: []                         # PRs coming from these branches
  excludeHeadBranches: ["renovate/**"]
```

- On a **rule**: the rule only applies to matching pull requests.
- Under **`settings`**: other pull requests aren't inspected at all and get a passing
  "Not applicable" status.

The example workflow re-runs when a pull request's target branch changes, so retargeting a PR to
`main` triggers the check. The CLI uses the branch names from `--base`/`--head`, or
`--target-branch`/`--source-branch`.

### Priority repositories

| Field | Description |
|---|---|
| `name`, `reason` | Shown in the report. |
| `repositories` | `owner/repo` globs, e.g. `acme/payments-*` (case-insensitive). |
| `blockOn` | Lower threshold for these repositories. |
| `severityBoost` | Raise every finding by 0–3 levels (capped at critical). |
| `requiredApprovals` | More approvals. |
| `allowBypass` | `false` disables the bypass command. |

If a repository matches several groups, the strictest value of each setting applies.

### Settings

| Setting | Default | Description |
|---|---|---|
| `blockOn` | `high` | Minimum severity that needs security review. Lower findings are listed as non-blocking. |
| `requiredApprovals` | `1` | Approvals needed from the security team. |
| `staleApprovals` | `flagged-changes` | `flagged-changes` or `any-change`; see above. |
| `securityTeam.teams` / `.users` | `[]` | Security reviewers. Teams are `org/slug` or `slug`. |
| `requestReview` | `true` | Request review from the security team when a PR gets blocked. |
| `when` | | Only inspect matching pull requests (see Conditions). |
| `ignorePaths` | `[]` | Globs never inspected (vendored code, snapshots, …). |
| `fileContentLimit` | `300` | Max files read in full for `fileContent` rules per run. |
| `integrityRule` | `true` | Built-in critical rule for the inspector config, the workflow running it and `CODEOWNERS`. |
| `bypass.enabled` / `.command` / `.teams` / `.users` / `.includeSecurityTeam` / `.allowAuthor` / `.minReasonLength` | `true` / `/security-bypass` / `[]` / `[]` / `true` / `false` / `10` | Bypass behaviour. |
| `recheckCommand` | `/security-recheck` | Re-evaluate command. |
| `labels.reviewRequired` / `.approved` / `.bypassed` | `security-review-required` / `security-approved` / `security-bypassed` | Labels applied; set any to `false` to disable. |
| `report.maxSnippetLines` / `.maxFilesPerComponent` / `.showNonBlocking` / `.commentOnNonBlocking` | `20` / `25` / `true` / `false` | Report size and verbosity. |

### Repository-local rules

A repository can add its own rules in `.github/security-inspector.yml` (see
[`examples/local-rules.yml`](examples/local-rules.yml)). When a central policy is configured,
the local file can only **add** rules. It can't change settings or override central rules, and the
inspector warns about any attempt to. Without a central policy, the local file is the whole policy.

## Action inputs

| Input | Default | Description |
|---|---|---|
| `github-token` | `${{ github.token }}` | Reads the PR; writes status, comment, labels. |
| `org-token` | `github-token` | Reads the central policy repo and team membership (see below). |
| `policy-repository` | | Central policy repository, e.g. `acme/security-policies`. |
| `policy-ref` | default branch | Branch/tag/SHA of the policy. |
| `policy-path` | `security-inspector-policy.yml` | Policy file in the policy repository. |
| `local-config-path` | `.github/security-inspector.yml` | Local rules/policy (read from the base commit). |
| `status-context` | `Security Inspector` | Name of the required status. |
| `bot-login` | `github-actions[bot]` | Account behind `github-token`. Set to `<app-slug>[bot]` when using an app token there. |
| `blocked-state` | `failure` | `failure` or `pending` while review is required. |
| `fail-on-block` | `false` | Also fail the job (the status is the recommended gate). |
| `pull-request-number` | | For `workflow_dispatch` runs. |

Outputs: `decision`, `blocking-count`, `finding-count`, `components`, `priority`.

### Tokens

The default `GITHUB_TOKEN` can't read other private repositories or team membership. For a
central policy and `teams:` lists, pass an `org-token`, ideally from a GitHub App installed on the
organisation with **Contents: read** (policy repository) and **Members: read** (organisation).
The example workflow creates one with `actions/create-github-app-token`. Without it, keep the policy
in each repository and list reviewers under `users:`.

## Security model

- **The PR can't change the rules it's checked against.** The local policy is read from the base
  commit, the central policy from the security team's repository, and with `pull_request_target`
  the workflow file itself comes from the base branch.
- **`pull_request_target` is safe here.** The inspector never checks out or runs pull request code;
  it only reads the diff through the API. Don't add steps that check out the PR head to this workflow.
- **Tampering is flagged.** The built-in integrity rule marks changes to the inspector config, the
  workflow that runs it and `CODEOWNERS` as critical.
- **Bypass records are checked, not trusted.** A record only counts if the inspector's own account
  posted it and nobody edited it since, and if the command comment it refers to still exists, is
  unedited, and was written by someone who is still authorised.
- **Limitations.** This is a review-routing gate, not protection against malicious admins. Anyone
  who can edit branch protection, or push workflows that run with a write token, can interfere with
  commit statuses. For stronger guarantees, run the inspector with a dedicated GitHub App identity
  (`github-token` + `bot-login`), restrict who can change workflows with rulesets, and pin the
  required status to that app. Rules are pattern-based: they catch the changes you describe, not
  every possible security-relevant change.

## CLI

The same engine runs locally, so the security team can test rules and developers can check a
branch before pushing:

```sh
npx github:asii-mov/inspector-repo validate policy.yml [--local .github/security-inspector.yml]
npx github:asii-mov/inspector-repo scan --policy policy.yml [--repo acme/web] [--base origin/main] [--format text|markdown|json]
git diff main... | npx github:asii-mov/inspector-repo scan --policy policy.yml --diff -
```

`scan` exits with `1` when security review would be required, so it also works as a pre-push hook.

## Development

```sh
npm ci
npm run typecheck
npm test          # unit tests + an end-to-end run of the action against a fake GitHub API
npm run build     # bundles dist/index.mjs (action) and dist/cli.mjs (CLI); commit dist/
```

Synthetic pull request scenarios (a realistic set of auth, UI, infra and dependency changes run
against the example policy) live on the [`tests`](https://github.com/asii-mov/inspector-repo/tree/tests)
branch, separate from `main`. To run them against the current code, merge `main` into `tests`
and run `npm test` there.

| Path | Contents |
|---|---|
| `src/policy/` | Policy schema (zod), YAML loading, merging local rules |
| `src/diff/` | Unified diff parsing |
| `src/engine/` | Scanning, priority profiles, approvals and bypass validation, the decision. Pure logic, no I/O |
| `src/report/` | Markdown / text rendering |
| `src/github/` | GitHub API access |
| `src/action/main.ts` | Action entry point |
| `src/cli.ts` | CLI entry point |

Releases: build, commit `dist/`, tag `vX.Y.Z` and move the `v1` tag.
