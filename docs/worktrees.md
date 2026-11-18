# Parallel Worktrees Convention

USOC uses git worktrees so parallel OpenCode agents can work in the same repository
without overwriting each other's files or sharing mutable runtime state.

## Why

- Each agent gets an **isolated checkout** and its own branch, so no file conflicts.
- The runtime state that matters here is **not Terraform/Kubernetes locks** (USOC has
  none) — it is the gitignored directories `workspace/`, `workspace-frag/`, and
  `secrets/`, plus the append-only evidence chain. Those are untracked, so a fresh
  worktree starts clean and evidence cannot be corrupted across agents.
- Worktrees share one `.git` object store and **branch namespace**: each agent must
  stay on its own `work/*` branch. Never check out another worktree's branch.

## Branches and paths

All work branches are created from `dev` (the integration branch) and merge back to
`dev` via PR, where CI (`pytest`) is required:

| Worktree | Branch | Purpose |
|---|---|---|
| Primary checkout | `main` | Tagged releases, protected |
| `work/cyber` | `work/cyber` | Cyber vertical |
| `work/finance` | `work/finance` | FinOps / banking vertical |
| `work/healthcare` | `work/healthcare` | Clinical / healthcare vertical |

Worktrees live under the OpenCode worktree root, outside the primary checkout.
`main` and `production` are protected and are **not** parallel sandboxes.

## Agent workflow

1. Work in your assigned worktree only; confirm with `git branch --show-current`.
2. Commit on your `work/*` branch. Do not force-push or switch branches.
3. When done, open a PR `work/<vertical>` -> `dev` and let CI run.
4. After merge, delete the branch and recreate the worktree from fresh `dev` if needed.

## Setup / teardown

Worktrees are managed through the OpenCode worktree tools (`worktree_create`,
`worktree_list`, `worktree_remove`). Note that `worktree_create` produces a
**detached HEAD**; always create a real branch in the new worktree immediately:

```sh
git -C <worktree-path> switch -c work/<vertical> dev
```

To tear down: remove the worktree, then `git branch -D work/<vertical>`.
