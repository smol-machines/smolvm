# smolvm-embedded

Public embedded Node.js SDK package.

This package will expose the TypeScript API surface and resolve the correct
internal platform package at install/runtime.

Current local workflow from the `smolvm` repo:

```bash
cd sdks/node
npm install
npm run build
npm test
npm run smoke
```

Example:

```bash
cd sdks/node/smolvm-embedded
npx tsx examples/basic.ts
```

The package resolves one of the internal platform packages at runtime:

- `smolvm-embedded-darwin-arm64`
- `smolvm-embedded-darwin-x64`
- `smolvm-embedded-linux-arm64-gnu`
- `smolvm-embedded-linux-x64-gnu`

Those packages carry the `.node` binary plus the bundled `libkrun` and
`libkrunfw` libraries staged from the `smolvm` repo's `./lib` directory.
