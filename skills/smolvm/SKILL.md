---
name: smolvm
description: Runs work in a smolvm microVM, a real VM with its own kernel that boots in under a second and can be checkpointed, rewound and branched. Use when code must run isolated from this host, when an agent needs a disposable or persistent machine, or to try several approaches from one saved state. Routes to the task's own skill.
---

# smolvm

smolvm runs each workload in a hardware-isolated microVM: its own Linux kernel, any OCI image, no
daemon. A running machine can be saved, rewound, or branched into copies that continue from the
same point. This skill picks the task; the task's own skill has the tested procedure.

## First, is smolvm installed and can this host boot a VM?

```bash
smolvm --version && smolvm machine run --image alpine -- true && echo ok
```

If that fails, follow [install](../install/SKILL.md) before anything else.

## Pick the task

| The job | Skill |
|---|---|
| Run code you do not trust, with no network unless granted | [throwaway-machine](../throwaway-machine/SKILL.md) |
| Run a coding agent with full permissions inside a machine | [coding-agent](../coding-agent/SKILL.md) |
| Keep a machine with dependencies installed and come back to it | [dev-env](../dev-env/SKILL.md) |
| Save, rewind, pause or branch a running machine | [branch-and-checkpoint](../branch-and-checkpoint/SKILL.md) |
| Give a workload an API key it can use but never read | [credentials](../credentials/SKILL.md) |
| Run Docker inside a machine | [docker-in-machine](../docker-in-machine/SKILL.md) |
| Use a host NVIDIA GPU from a machine | [gpu-cuda](../gpu-cuda/SKILL.md) |
| Ship a machine to another host as one file | [pack](../pack/SKILL.md) |
| Drive machines from code over the local HTTP API | [local-api](../local-api/SKILL.md) |
| Stop everything and prove nothing is left | [teardown](../teardown/SKILL.md) |

## Quick reference

```bash
smolvm machine run --net --image python:3.12-alpine -- python3 -c 'print(1)'   # one-off, removed on exit
smolvm machine create --net --name dev && smolvm machine start --name dev --branchable
smolvm machine exec --name dev -- sh -c 'echo hi'
smolvm machine branch --from dev --name try-1                                   # live copy-on-write child
smolvm machine stop --name try-1 && smolvm machine delete --name try-1 -f
```

Run `smolvm --help` or `smolvm machine <command> --help` for every flag. Networking is off unless
`--net` is given, and `--allow-host` limits it to named hosts.
