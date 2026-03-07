# Embedded Node SDK Workspace

This workspace contains:

- `smolvm-embedded`: the public package users install
- `smolvm-embedded-*`: internal platform packages that carry the `.node`
  binary plus bundled `libkrun` and `libkrunfw`

Users should only install `smolvm-embedded`. The platform packages are an
implementation detail used by npm's optional dependency resolution.

Local maintainer workflow:

```bash
cd sdks/node
npm install
npm run build
npm test
npm run smoke
```

During local development, `npm install` may warn about unpublished optional
platform packages. That is expected. Local builds resolve the sibling
`smolvm-embedded-*` package directories directly instead of relying on npm to
install those internal packages.

Repo-root build entrypoint:

```bash
./scripts/build-embedded-node.sh
```
