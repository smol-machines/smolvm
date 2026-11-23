# Serial devices

`--serial DEVICE[:BAUD]` passes a host serial device (a USB-serial adapter, an
Arduino, an ESP32 dev board, a modem) into a machine. The guest sees it as a tty:
`/dev/ttySMOL0` for the first `--serial`, `/dev/ttySMOL1` for the second, and so on.
It works on `machine run` and `machine create`, in a bare machine and inside its
container, and any uid in the guest may open it.

```bash
# macOS: adapters appear as /dev/cu.usbserial-*, /dev/cu.usbmodem-*
smolvm machine run --serial /dev/cu.usbserial-0001:115200 -- sh -c 'cat /dev/ttySMOL0'

# Linux: /dev/ttyUSB* or /dev/ttyACM*
smolvm machine create --name bench --serial /dev/ttyACM0 --net --image alpine
smolvm machine start --name bench
smolvm machine exec --name bench -- sh -c 'printf "AT\r" > /dev/ttySMOL0'
```

`BAUD` defaults to 115200. On Linux it must be a standard rate (1200 to 3000000);
on macOS any rate the adapter accepts works.

## How it works

The machine's VM runs as an unprivileged per-machine user, so it never opens the
device itself. At start, a small bridge process opens the device as you, sets it
raw at the requested speed, then drops to the machine's user and relays the bytes
over the same host↔guest channel as `--mount-socket`. Inside the guest the agent
gives programs a pty linked at `/dev/ttySMOL<n>`. The bridge stops with the
machine.

## Limits

- The line speed is set on the host when the machine starts. Changing it from
  inside the guest (`stty`) changes only the pty, not the adapter.
- Modem-control lines (DTR/RTS) are not passed through, so tools that reset a
  board through them, such as `esptool.py` auto-reset on ESP32 boards, need the
  board put into download mode by hand (hold BOOT, tap RESET).
- One program in the guest should hold the tty at a time, as with a real port.
- The device must exist when the machine starts: an unplugged adapter fails the
  start with `serial device /dev/...: No such file or directory`. If an adapter is
  unplugged while the machine runs, the bridge stops; restart the machine after
  plugging it back in.
- On Linux, your user needs access to the device, usually through the `dialout`
  or `uucp` group.
- USB devices other than serial adapters (JTAG probes, DFU, HID) are not passed
  through.
