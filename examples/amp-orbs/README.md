# Amp orbs on smol machines

[Amp](https://ampcode.com) runs an agent's work in an *orb*: a machine that
clones the repository, runs setup and runs the agent's tools. With
[self-hosted orbs](https://ampcode.com/docs/orbs/self-hosted), Amp sends spawn,
pause and delete requests to a dispatch program you choose. These dispatch
programs make every orb a smol machine.

| Script | Orbs run on |
|---|---|
| `dispatch-smolvm.sh` | your own x86_64 Linux host with KVM |
| `dispatch-smol-cloud.sh` | [smol cloud](https://smolmachines.com) |

Both pause an orb by saving its RAM and disk, so it wakes with its processes
still running, not just its files.

Amp's orb image is `linux/amd64`, so orbs need x86_64 hardware: a Linux host
for `dispatch-smolvm.sh`, or smol cloud, which places them on x86_64 workers.

## Set up

1. In Amp, open **Settings → Orbs**, click **Add Orb Provider**, name it (for
   example `smol`) and copy the `aop_live_…` token. Amp shows it once.
2. On the machine that will run the provider, install the
   [Amp CLI](https://ampcode.com/docs/cli)
   (`curl -fsSL https://ampcode.com/install.sh | bash`). The provider makes
   only outbound HTTPS connections, so it needs no open ports.
3. Run the provider with one of the dispatch programs, and keep it running
   under a service manager:

   **Your own host** (needs [smolvm](https://smolmachines.com) on `PATH`, or
   `SMOLVM` set to its path):

   ```bash
   export AMP_ORB_PROVIDER_TOKEN="aop_live_…"
   amp orb provider "$PWD/dispatch-smolvm.sh"
   ```

   **smol cloud** (needs `curl` and `jq`, and an API key from
   [smolmachines.com](https://smolmachines.com)):

   ```bash
   export AMP_ORB_PROVIDER_TOKEN="aop_live_…"
   export SMOL_API_KEY="…"
   amp orb provider "$PWD/dispatch-smol-cloud.sh"
   ```

4. In a new Amp thread, click **Orb**, open the type dropdown and choose your
   provider under **Self-Hosted**, or run
   `amp -ox "your first message" --orb-provider smol`.

## How the operations map

| Amp sends | `dispatch-smolvm.sh` | `dispatch-smol-cloud.sh` |
|---|---|---|
| `spawn` | create the machine from `ORB_IMAGE` and start it, resume a paused one, or start a stopped one; then run `amp orb bootstrap` in the background as `user` | the same, through the cloud API; the orb's machine is found by its `amp-orb` label |
| `pause` | `smolvm machine pause` (RAM and disk) | `POST /v1/machines/:id/pause` (RAM and disk) |
| `delete` | `smolvm machine delete` | `DELETE /v1/machines/:id` |

Every operation is safe to repeat, as Amp requires. The token reaches the orb
without appearing on a command line: `dispatch-smolvm.sh` passes it as a
secret environment reference, and `dispatch-smol-cloud.sh` sends it in the
request body.

## Sizing

Each orb gets 4 vCPUs, 8 GiB of memory and a 40 GiB disk by default. Set
`ORB_CPUS`, `ORB_MEMORY_MIB` (`ORB_MEMORY_MB` for the cloud) and
`ORB_STORAGE_GIB` (`ORB_DISK_GB` for the cloud) in the provider's environment
to change them.

## Measured

Amp's own orb image, each operation timed end to end through the dispatch
program. `dispatch-smolvm.sh` ran smolvm 1.31.1 on an x86_64 Linux host with
the image already pulled; `dispatch-smol-cloud.sh` ran against smol cloud.

| Operation | Your own host | smol cloud |
|---|---|---|
| spawn a new orb | 2.9 s | 3.5 s |
| pause | 0.6–0.7 s | 4.2–5.0 s |
| spawn a paused orb (resume) | 0.9 s | 2.6 s |
| delete | 31 ms | 0.7 s |

On both, a file written in the orb and a background process started in it
were still there after pause and resume, and every operation repeated
succeeded without changing anything.
