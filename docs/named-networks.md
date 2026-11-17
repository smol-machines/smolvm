# Named networks

Machines that join the same named network reach each other directly by IP.
Networks with different names are isolated from each other, and members keep
their normal outbound access.

```sh
smolvm machine create --name db  --image alpine --network lab
smolvm machine create --name app --image alpine --network lab
smolvm machine start --name db && smolvm machine start --name app
smolvm machine exec --name db -- ip -4 addr show eth0   # inet 100.96.1.2/30
```

Each member gets a `100.96.N.2` address leased when it starts, so it can change
after a stop and start: read it rather than hardcoding it. Names do not
resolve; `app` reaches `db` by address only. Each network leases from its own
pool, so two networks can hand out the same address.

`--network` implies `--net`, needs the virtio-net backend (TSI is refused) and
cannot be combined with `--guest-subnet`.
