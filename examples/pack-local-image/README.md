# Pack Local Image Example

This example shows the supported way to turn a locally built Docker image into a `.smolmachine`:

1. build the local image from the `Dockerfile` in this directory
2. push it to a temporary local registry through the helper script
3. run `smolvm pack create` against that local-registry reference

## Files

- `Dockerfile`: tiny Alpine image that copies `hello.txt` into `/app/hello.txt`
- `hello.txt`: local file baked into the image
- `hello-local` and `hello-local.smolmachine`: sample packed outputs from this flow

## Build The Local Image

From this directory:

```bash
cd examples/pack-local-image
docker build -t hello-local:dev .
```

You can confirm the local image works before packing it:

```bash
docker run --rm hello-local:dev
```

That should print the banner from the image and the contents of `hello.txt`.

## Pack It Into A `.smolmachine`

From the repository root:

```bash
./scripts/pack-local-image.sh --image hello-local:dev --output ./examples/pack-local-image/hello-local
```

What the script does:

1. starts a temporary local registry on `localhost:5051`
2. tags `hello-local:dev` as `localhost:5051/hello-local:dev`
3. pushes that tag to the local registry
4. runs `smolvm pack create --image localhost:5051/hello-local:dev -o ./examples/pack-local-image/hello-local`
5. removes the temporary registry container and temporary registry tag

Expected outputs:

```text
./examples/pack-local-image/hello-local
./examples/pack-local-image/hello-local.smolmachine
```

## Verify The Packed Output

Run the packed launcher directly:

```bash
./examples/pack-local-image/hello-local run
```

Or create a managed machine from the sidecar:

```bash
smolvm machine create hello-local-vm --from ./examples/pack-local-image/hello-local.smolmachine
smolvm machine start --name hello-local-vm
smolvm machine exec --name hello-local-vm -- cat /app/hello.txt
```