---
name: coding-agent
description: Runs a coding agent (Claude Code, OpenCode, Codex, pi or any other) inside a persistent smolvm machine, so it can run with full permissions without touching the host, and with its API key kept outside the machine. Also covers running several attempts in parallel from one warm machine and keeping the best. Use when someone wants to sandbox their coding agent, run many tasks at once with one agent per task instead of creating a git worktree for each, run it in skip-permissions or YOLO mode safely, try a task several ways at once, or give it a disposable environment it can install anything into. Do not use it to run untrusted code with no network; use throwaway-machine for that.
---

# A coding agent in a machine

Verified on **smolvm v1.27.4** on Linux x86_64, 2026-10-14, on **v1.29.0** on macOS arm64,
2026-10-15, and on **v1.36.0** on macOS arm64, 2026-11-23 (the first two procedures). The
many-tasks procedure was verified on **v1.37.0** on Linux x86_64, 2026-11-23, with two tasks
running headless at once, up to the API request (made with a placeholder key). Done means the agent
runs inside the machine, the real API key never appears in it, and the agent's work reaches the
host repo.

## Procedure: one agent on your project

**1. Get the Smolfile into the project.** Edit the `npm install` line in `init` to the agents you
use; any install command works.

```bash
curl -fsSL https://raw.githubusercontent.com/smol-machines/smolvm/main/docs/coding-agent/assets/agent.smolfile -o Smolfile
```

**2. Create and start the machine, with the key kept outside.**

```bash
smolvm machine create --name agent -s Smolfile \
  --credential anthropic=ANTHROPIC_API_KEY@api.anthropic.com
smolvm machine start --name agent      # first start runs init: under a minute once the image is pulled
```

`--credential NAME=ENV_VAR@HOST` uses the **same variable name on both sides**: the real value is
read from the host's `ANTHROPIC_API_KEY`, and the guest's `ANTHROPIC_API_KEY` holds only a
placeholder that the host swaps for the real value on HTTPS requests to `api.anthropic.com`.
`create` prints one line per binding saying exactly that; check it names the variable your agent
reads. For OpenAI-based agents use `openai=OPENAI_API_KEY@api.openai.com`. `machine credentials
add` adds or changes a binding on a running machine without a restart.

The Smolfile forwards your SSH agent, so `start` needs `SSH_AUTH_SOCK` set on the host: without it,
it stops with `ssh-agent: SSH_AUTH_SOCK is not set`. Start one with `eval $(ssh-agent)`, or delete
the `[auth]` block.

**3. Run the agent.**

```bash
smolvm machine exec --name agent -it -- claude --dangerously-skip-permissions
smolvm machine exec --name agent -it -- opencode
```

`machine shell --name agent` gives a shell in `/workspace` for anything else.

**4. Check git.** `smolvm machine exec --name agent -- git status` must print the repo's status,
not `dubious ownership`; if it does not, the `safe.directory` line in `init` did not run.

**5. Stop or delete.** `machine stop --name agent` keeps the installed agents for next time, and the
next start takes about a second. `machine delete --name agent -f` removes the machine; the project
stays on the host.

## Procedure: several attempts in parallel, keep the best

The project is mounted from the host above, so the agent's edits live on your disk and a branch of
the machine would not carry them. To branch the work itself, keep the repo inside the machine.

**1. Create a source machine without the host mount** and start it as a branch source:

```bash
curl -fsSL https://raw.githubusercontent.com/smol-machines/smolvm/main/docs/coding-agent/assets/agent-branch.smolfile -o Smolfile
smolvm machine create --name agent-src -s Smolfile \
  --credential anthropic=ANTHROPIC_API_KEY@api.anthropic.com
smolvm machine start --name agent-src --branchable
```

**2. Put the repo in it.**

```bash
git bundle create /tmp/repo.bundle --all
smolvm machine cp /tmp/repo.bundle agent-src:/workspace/repo.bundle
smolvm machine exec --name agent-src -- sh -c 'cd /workspace && git clone -q repo.bundle proj'
```

Install dependencies and get the project to the state every attempt should start from, with `exec`
or an agent session in `/workspace/proj`.

**3. Branch it.** Each child is a full copy of the running machine: files, installed dependencies
and running processes.

```bash
smolvm machine branch --from agent-src --count 3 --name-prefix try --no-wait-ready
```

**4. Run one attempt per child**, for example a different prompt in each:

```bash
smolvm machine exec --name try-0 -it -- sh -c 'cd /workspace/proj && claude --dangerously-skip-permissions'
```

**5. Bring the best one back with git**, then delete the children:

```bash
smolvm machine exec --name try-1 -- sh -c 'cd /workspace/proj && git format-patch origin/HEAD..HEAD --stdout' | git am
for m in try-0 try-1 try-2; do smolvm machine delete --name "$m" -f; done
```

The agent must commit its work in the child for `format-patch` to carry it. The source keeps
running, so you can branch it again for the next task.

## Procedure: many tasks at once, one branch per task

Use this instead of a git worktree per task. Each worktree is a full checkout, and each agent in it
installs and builds its own dependencies. A branch of a warm machine shares all of that copy-on-write,
so a task costs only what it changes: four branches of a machine holding 1 GiB of build output added
4 MiB, where four worktrees would add about 4 GiB. Deleting a branch frees its space at once.

**1. Once per repo: a running source machine with the repo and its dependencies inside.**

```bash
curl -fsSL https://raw.githubusercontent.com/smol-machines/smolvm/main/docs/coding-agent/assets/agent-branch.smolfile -o Smolfile
smolvm machine create --name myrepo-src -s Smolfile \
  --credential anthropic=ANTHROPIC_API_KEY@api.anthropic.com
smolvm machine start --name myrepo-src --branchable
smolvm machine exec --name myrepo-src -- sh -c '
  git config --global user.name "agent" && git config --global user.email "agent@example.com"
  git clone -q git@github.com:ORG/REPO.git /workspace/proj && cd /workspace/proj && npm ci'
```

The clone over SSH works because the Smolfile forwards your SSH agent; the keys never enter the
machine. Replace `npm ci` with whatever installs and builds the project. Leave the source running.

**2. Per task: branch, then run the agent headless in the branch.**

```bash
smolvm machine branch --from myrepo-src --name task-fix-login
smolvm machine exec --name task-fix-login -- sh -c 'cd /workspace/proj && git checkout -qb fix-login &&
  claude -p "Fix the login redirect bug. Run the tests. Commit, then git push -u origin fix-login." \
    --dangerously-skip-permissions'
```

A branch takes well under a second. Run one of these per task at the same time (each `exec` in the
background, or in its own terminal); the branches are independent of each other and of the source.
To watch or steer one, use `exec -it ... claude --dangerously-skip-permissions` instead of `-p`.
Branch each task with its own `--name`: `--count N` waits for the source to declare a branch point
unless `--no-wait-ready` is passed.

**3. Collect the work.** The agent pushed its branch through the forwarded SSH agent; open a pull
request as usual. Without push access, bring it back with `git format-patch` as in the previous
procedure.

**4. Delete the branch** when the task is merged or dropped:

```bash
smolvm machine delete --name task-fix-login -f
```

**Keeping the source current.** Branches start from the source as it is when they are made, so pull
and rebuild there now and then; earlier branches are unaffected:

```bash
smolvm machine exec --name myrepo-src -- sh -c 'cd /workspace/proj && git pull -q && npm ci'
```

**From Claude Code.** With this skill installed (see `README.md`), tell the session to run each
task in its own branch of `myrepo-src` rather than in a worktree. It runs steps 2 to 4 for each task
with its shell tool and reports which branches were pushed.

## Notes

- `init` runs once. Changing it later needs a new machine, or run the new commands with `exec`.
- Other agents install the same way: pi is `npm install -g @mariozechner/pi-coding-agent`.
- Subscription logins (Claude Pro/Max, ChatGPT plans) are not covered here; this procedure was
  verified with API keys.
- To keep the agent off your LAN and the host's ports, add `block_private = true` under
  `[network]` (from v1.28.1). See `README.md`.
- An agent that needs Docker: add `"/var/lib/docker", "/var/lib/containerd"` to `[dev] volumes`
  (from v1.28.1) and see [docker-in-machine](../docker-in-machine/README.md).
