# smolvm-embedded for Python

Public embedded Python SDK package.

## Build

```bash
cd sdks/python
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip maturin
./scripts/build-current-platform.sh
```

That stages bundled `libkrun`/`libkrunfw` plus a local `smolvm` boot helper
wrapper into the package and installs the extension into the active Python
environment with `maturin develop`.

## Usage

```python
from smolvm_embedded import Machine, MachineConfig

machine = Machine.create(MachineConfig(name="py-demo"))
result = machine.exec(["echo", "hello from python"])
print(result.stdout.strip())
machine.delete()
```

Run the local examples:

```bash
cd sdks/python
. .venv/bin/activate
python3 examples/basic.py
python3 examples/create_and_start.py
```
