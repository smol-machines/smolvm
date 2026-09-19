# smolvm documentation

One folder per task. Each topic holds a `README.md` with the facts and why they hold, and where a
procedure exists, a `SKILL.md` an agent can follow, with its own `scripts/` and `references/`.

Install a topic into an agent's skills directory with:

```bash
npx skills add smol-machines/smolvm --skill <topic>
```

`llms.txt` lists every `SKILL.md` path for agents that read the tree directly.

## Topics

| Topic | What it covers | Procedure |
|---|---|---|
| [sandbox](sandbox/README.md) | running untrusted code in a throwaway machine, with egress granted one host at a time | [SKILL.md](sandbox/SKILL.md) |
