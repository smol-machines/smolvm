---
name: smolvm-sandbox
description: Execute untrusted code, run test suites, install dependencies, and build software in isolated, ephemeral microVM sandboxes (<200ms boot, hardware-assisted virtualization, zero host pollution). Use whenever running unverified code, running build scripts from unfamiliar repositories, or providing an isolated execution environment.
---

# smolvm Sandbox Skill

Use `smolvm` to run commands, test suites, and build scripts inside isolated, lightweight Linux microVMs. `smolvm` boots in under 200ms directly via host hypervisors (`Hypervisor.framework` on macOS, KVM on Linux, WHP on Windows) without background daemons or Docker.

## When to Use This Skill

- **Running Untrusted Code**: Executing Python, Node.js, Rust, Go, or bash scripts from unfamiliar repositories.
- **Clean-room Testing**: Running tests without pollution from local environment variables, system packages, or global caches.
- **Dependency Sandboxing**: Running `npm install`, `pip install`, `cargo build` in an ephemeral environment that discards modifications on completion.
- **Cross-Platform MicroVM Execution**: Running Linux binaries locally on macOS Apple Silicon or Linux hosts with hardware isolation.

---

## Quick Reference Recipes

### 1. Run a One-Off Command in an Ephemeral MicroVM (Recommended Default)

```bash
# Mount current directory to /workspace and run command in alpine or ubuntu
smolvm machine run \
  --image alpine \
  -v "$(pwd):/workspace" \
  -w /workspace \
  -- echo "Hello from isolated sandbox"
```

### 2. Run Tests / Builds with Controlled Outbound Networking

Keep networking disabled by default. When downloading packages is strictly required, enable network access or restrict egress:

```bash
# General outbound network access for package managers
smolvm machine run \
  --net \
  --image python:3.12-alpine \
  -v "$(pwd):/workspace" \
  -w /workspace \
  -- sh -c "pip install -r requirements.txt && pytest"

# Restricted egress to specific package repositories or hosts
smolvm machine run \
  --net \
  --allow-host pypi.org \
  --allow-host files.pythonhosted.org \
  --image python:3.12-slim \
  -v "$(pwd):/workspace" \
  -w /workspace \
  -- pytest
```

### 3. Inject API Keys & Secrets Securely

Never pass plain-text secrets in the command string. Reference host environment variables or files:

```bash
# Injects $OPENAI_API_KEY from the host into guest env without CLI exposure
smolvm machine run \
  --net \
  --image python:3.12-alpine \
  --secret-env OPENAI_API_KEY=OPENAI_API_KEY \
  -v "$(pwd):/workspace" \
  -w /workspace \
  -- python3 test_openai_integration.py
```

### 4. Interactive Debugging & Shell Access

When you need an interactive session in the sandbox:

```bash
smolvm machine run \
  --net \
  -it \
  --image ubuntu \
  -v "$(pwd):/workspace" \
  -w /workspace \
  -- /bin/bash
```

### 5. Persistent Sandbox Workflow (Stateful Development)

When repeated commands must preserve installed dependencies across steps:

```bash
# 1. Create and start a persistent sandbox
smolvm machine create --name dev-sandbox --image ubuntu:24.04 --net
smolvm machine start --name dev-sandbox

# 2. Run sequential commands (package installations and environment persist)
smolvm machine exec --name dev-sandbox -- apt-get update
smolvm machine exec --name dev-sandbox -- apt-get install -y build-essential curl
smolvm machine exec --name dev-sandbox -v "$(pwd):/workspace" -w /workspace -- make test

# 3. Clean up when finished
smolvm machine stop --name dev-sandbox
smolvm machine delete --name dev-sandbox
```

---

## Security & Isolation Guardrails

| Rule | Guideline | Why |
|---|---|---|
| **Disable Network by Default** | Omit `--net` unless dependencies must be fetched. | Prevents data exfiltration or unintended outbound network calls. |
| **Restrict Host Mounts** | Only mount the project directory (`-v "$(pwd):/workspace"`). | Never mount root `/`, `$HOME`, or `~/.ssh` into an untrusted guest. |
| **No SSH Agent Forwarding** | Do NOT pass `--ssh-agent` unless authenticated git clone is requested. | Protects host private SSH keys from guest processes. |
| **Ephemeral by Default** | Use `smolvm machine run` instead of `machine create`. | State, rootfs mutations, and temporary files are automatically purged on exit. |

---

## Pre-flight Checklist for Coding Agents

1. **Verify `smolvm` is installed**:
   ```bash
   smolvm --version
   ```
2. **Select the appropriate base image**:
   - Small & Fast: `alpine:latest` (~5MB) or `python:3.12-alpine`
   - Full Linux / glibc: `ubuntu:24.04` or `debian:13-slim`
   - Specific Toolchain: `node:20-alpine`, `rust:alpine`, `golang:alpine`
3. **Always set working directory**:
   - Use `-v "$(pwd):/workspace" -w /workspace` so output artifacts and edits reflect on the host project.
