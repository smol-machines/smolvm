<p align="center">
  <img src="../../assets/logo.png" alt="smol machines" width="80">
</p>

<p align="center">
  <a href="https://discord.gg/E5r8rEWY9J"><img src="https://img.shields.io/badge/Discord-Join-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://github.com/smol-machines/smolvm/releases"><img src="https://img.shields.io/github/v/release/smol-machines/smolvm?label=Release" alt="Release"></a>
  <a href="https://github.com/smol-machines/smolvm/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://www.npmjs.com/package/smolmachines"><img src="https://img.shields.io/npm/v/smolmachines?label=npm&logo=npm" alt="npm"></a>
  <a href="https://pypi.org/project/smolmachines/"><img src="https://img.shields.io/pypi/v/smolmachines?label=PyPI&logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://crates.io/crates/smolmachines"><img src="https://img.shields.io/crates/v/smolmachines?label=crates.io&logo=rust" alt="crates.io"></a>
</p>

<p align="center">
  <sub><a href="../../README.md">English</a> · <a href="README.zh-CN.md">中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.ru.md">Русский</a> · <a href="README.es.md">Español</a> · <b>Deutsch</b></sub>
</p>

smolvm
======

**Verzweigbare microVMs für KI-Agenten.**
Betten Sie leichtgewichtige virtuelle Maschinen in Ihre Software ein und nutzen Sie sie für portable Entwicklungsumgebungen und die lokale Ausführung in einer Sandbox.

Installation
------------

```bash
brew install smol-machines/tap/smolvm                  # macOS (Homebrew)
curl -sSL https://smolmachines.com/install.sh | bash   # macOS + Linux
```

Windows: Entpacken Sie das `windows-x86_64`-[Release](https://github.com/smol-machines/smolvm/releases) und führen Sie `smolvm.exe` aus (erfordert die [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)). Coding-Agenten: Führen Sie nach der Installation `smolvm --help` aus, um alle Befehle kennenzulernen.

Die Dokumentation für Menschen und Agenten liegt unter [`docs/`](../README.md). Für jede Aufgabe gibt es einen Ordner mit einer `README.md`, die die Fakten enthält, sowie einer `SKILL.md`, deren Anweisungen ein Agent befolgen kann, und den zugehörigen Skripten. Daneben befindet sich die Referenzseite für die jeweilige Funktion.

Schnellstart
------------

```bash
smolvm machine run --net --image alpine -- uname -a          # one-off VM, removed on exit
smolvm machine run --net -it --image alpine -- /bin/sh       # interactive shell
```

Lokal
-----

Echte VMs mit eigenem Kernel, kostenlos auf Ihrem Laptop oder Ihren eigenen Servern. Sie booten in weniger als einer Sekunde. Der Arbeitsspeicher wird elastisch zugewiesen, sodass der Host nur so viel bereitstellt, wie der Gast nutzt. Maschinen bleiben über Neustarts hinweg erhalten, und jedes OCI-Image funktioniert, auch lokal erstellte Images.

```bash
smolvm machine create --net --name dev && smolvm machine start --name dev
smolvm machine exec --name dev -- apk add git
docker save myapp | smolvm machine run --image - -- ./app    # local image, no registry
```

Binden Sie mit `-v s3://bucket/prefix:/data` einen S3-, R2- oder MinIO-Bucket ein, siehe [Volumes](../volumes.md).

Deklarieren Sie eine Maschine in einem [Smolfile](../smolfile.md): Image, Ressourcen, Ports, Mounts und Netzwerkrichtlinie in einer einzigen eingecheckten Datei.

Einbettbar
----------

Steuern Sie Maschinen aus Ihrem eigenen Code über eine einheitliche `Machine`-API. Die SDKs laufen in Ihrem Prozess ohne Daemon, lokal oder auf [smol cloud](https://smolmachines.com).

```bash
npm install smolmachines     # Node / TypeScript
pip install smolmachines     # Python
cargo add smolmachines       # Rust
go get github.com/smol-machines/smol/sdk/go   # Go
```

```ts
import { Machine } from 'smolmachines';

const m = await Machine.create({ image: 'python:3.12-alpine', network: true });
const r = await m.exec(['python3', '-c', 'print(2 ** 10)']);
console.log(r.stdout); // 1024
await m.delete();
```

Quellcode und Dokumentation: [smol-machines/smol](https://github.com/smol-machines/smol) · [smolmachines.com/docs/sdk](https://smolmachines.com/docs/sdk)

Verzweigbar
-----------

Speichern Sie eine laufende Maschine mitten in der Ausführung, setzen Sie sie zurück oder verzweigen Sie sie in Kopien, die ab demselben Punkt weiterlaufen. Checkpoints erfassen RAM, CPU-Zustand und Datenträger; Branches sind Copy-on-Write-Kinder einer laufenden Maschine.

```bash
smolvm machine create --net --name agent --image alpine
smolvm machine start --name agent --branchable
smolvm machine branch --from agent --name try-1                   # live copy-on-write child
smolvm machine checkpoint --name agent -o agent.checkpoint        # save it, processes and all
smolvm machine create --name agent2 --from agent.checkpoint       # resume later or elsewhere
```

Mit `--from <checkpoint> --at '~N'` kehren Sie zu einer früheren Generation zurück (siehe `machine checkpoint-log`), und mit [Pausieren und Fortsetzen](../pause-resume.md) halten Sie eine Maschine an, ohne den Ausführungszustand zu verlieren. Mit einem auf einem arm64-Mac erstellten Checkpoint lässt sich die Ausführung unter arm64-Linux fortsetzen; siehe [Eine laufende Maschine von einem Mac auf Linux übertragen](../mac-to-linux.md). Weitere Informationen unter [Verzweigen](../branching.md) und [Inkrementelle Checkpoints](../incremental-checkpoints.md).

Portabel
--------

Packen Sie eine Maschine unabhängig von ihrer Konfiguration in eine einzige `.smolmachine`-Datei. Übertragen Sie sie in eine beliebige OCI-Registry oder führen Sie sie als eigenständige ausführbare Datei aus, die in weniger als 200 ms bootet, ohne dass etwas installiert werden muss.

```bash
smolvm machine stop --name dev && smolvm pack create --from-vm dev -o dev
smolvm pack push --file dev.smolmachine ghcr.io/you/dev:v1
smolvm pack create --image python:3.12-alpine -o ./python312
./python312 run -- python3 --version
```

Auch Checkpoints sind portabel: Stellen Sie einen Checkpoint auf einem anderen Host oder auf smol cloud wieder her.

Sicher
------

Jeder Workload erhält eine hardwareisolierte VM mit eigenem Kernel. Der Netzwerkzugriff ist standardmäßig deaktiviert, ausgehender Datenverkehr kann auf namentlich angegebene Hosts beschränkt werden, und Code kann Zugangsdaten verwenden, ohne sie jemals zu lesen.

Sicherheit liegt in gemeinsamer Verantwortung. smolvm schafft die Isolationsgrenze: eine separate VM und einen eigenen Kernel für jeden Workload. Nichts gelangt zum Host, sofern Sie es nicht erlauben. Sie entscheiden, was diese Grenze überschreiten darf. Alle Ordner, die Sie einbinden, Ports, die Sie öffnen, Hosts, die Sie zulassen, sowie Secrets und SSH-Agenten, die Sie weiterleiten, stehen dem Workload zur Verfügung. Geben Sie einem nicht vertrauenswürdigen Workload daher nur das, was er benötigt.

```bash
smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -qO- https://google.com   # blocked
smolvm machine run --net --image alpine --allow-host-pattern registry.npmjs.org -- wget -qO- https://registry.npmjs.org   # exact host only
NOTION_API_KEY=secret_… smolvm machine run --net --image alpine \
  --credential notion=NOTION_API_KEY@api.notion.com -- sh -c 'echo $NOTION_API_KEY'   # a placeholder
```

Siehe [Ersetzung von Zugangsdaten](../credential-substitution.md) und [Sicherheitsmodell](../security-model.md).
Verwenden Sie `--allow-host-pattern '*.example.com'`, um nur Subdomains zuzulassen; `--allow-host example.com` lässt die Domain selbst und
ihre Subdomains zu. Mit `smolvm machine update` lassen sich Einträge hinzufügen (`--allow-host`, `--allow-host-pattern`, `--allow-cidr`) und entfernen
(`--remove-allow-host`, Host oder Muster in derselben Schreibweise wie beim Hinzufügen; `--remove-allow-cidr`), auch bei einer laufenden Maschine,
die mit einer Zulassungsliste gestartet wurde: Eine Freigabe gilt ab der nächsten Verbindung oder Namensauflösung, und mit einem entfernten Host werden auch die für ihn gelernten Adressen entfernt.

Funktionsweise
--------------

Jeder Workload läuft in einer hardwarevirtualisierten VM mit eigenem Gastkernel auf [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (macOS), KVM (Linux) oder der [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/) (Windows). [libkrun](https://github.com/containers/libkrun) ist der VMM, und [libkrunfw](https://github.com/smol-machines/libkrunfw) liefert den Gastkernel. Images verwenden das [OCI](https://opencontainers.org/)-Format. Daher bootet jedes Image von Docker Hub, ghcr.io oder einer anderen Registry als microVM, ohne Docker-Daemon.

Standardwerte: 4 vCPUs, 8 GiB RAM. Der Arbeitsspeicher wird über virtio balloon elastisch zugewiesen, und inaktive vCPUs ruhen im Hypervisor, sodass eine Überprovisionierung fast nichts kostet. Mit `--cpus` und `--mem` können Sie die Standardwerte überschreiben.

Vergleich
---------

|                     | smolvm | Container | Colima | QEMU | Firecracker | Kata |
|---------------------|--------|------------|--------|------|-------------|------|
| Workload-Grenze      | VM + Gastkernel | Namespace + gemeinsam genutzter Kernel | Namespace in gemeinsam genutzter VM | VM + Gastkernel | VM + Gastkernel | VM pro Container |
| Bootzeit            | <200ms bis zur Einsatzbereitschaft des Gastagenten | ~100ms | ~Sekunden | ~15-30s | <125ms | ~500ms |
| Architektur         | Bibliothek (libkrun) | Daemon | Daemon (in VM) | Prozess | Prozess | Runtime-Stack |
| VMs pro Workload    | Ja | Nein | Nein (gemeinsam genutzt) | Ja | Ja | Ja |
| Nativ unter macOS   | Ja | Über Docker-VM | Ja (krunkit) | Ja | Nein | Nein |
| Einbettbares SDK    | Ja | Nein | Nein | Nein | Nein | Nein |
| Portable Artefakte  | `.smolmachine` | Images (benötigen Daemon) | Nein | Nein | Nein | Nein |

Plattformunterstützung
----------------------

| Host | Gast | Voraussetzungen |
|------|-------|-------------|
| macOS Apple Silicon | arm64 Linux | macOS 11+ |
| macOS Intel | x86_64 Linux | kein Release-Build veröffentlicht; ungetestet |
| Linux x86_64 | x86_64 Linux | KVM (`/dev/kvm`) |
| Linux aarch64 | aarch64 Linux | KVM (`/dev/kvm`) |
| Windows x86_64 | x86_64 Linux | Windows Hypervisor Platform (WHP) aktiviert |

Windows unterstützt portable Checkpoints, Pausieren/Fortsetzen und Branches mit `--freeze-source`. GPU-Beschleunigung ist weiterhin nicht verfügbar; siehe [bekannte Einschränkungen](../limitations.md).

Weiteres
--------

* [Kubernetes](../kubernetes.md): Führen Sie Pods über eine `RuntimeClass` als microVMs aus.
* [GPU und CUDA](../gpu.md): Vulkan über virtio-gpu / Venus sowie CUDA-API-Remoting.
* [Benannte Netzwerke](../named-networks.md): Maschinen, die einander per IP erreichen.
* [Geschachtelte Virtualisierung](../nested-virtualization.md): Führen Sie KVM, smolvm oder QEMU innerhalb einer Maschine aus.
* [Anzeige im Browser](../browser-display.md): der Desktop einer Maschine im Browser, mit Tastatur und Maus.
* [Beispiele](../../examples/): python, node, docker-in-vm, local-llm, headless-browser, doom.
* [Entwicklung](../DEVELOPMENT.md) · Benutzerdokumentation unter [smolmachines.com/docs](https://smolmachines.com/docs/), verfasst in [smol-machines/docs](https://github.com/smol-machines/docs) (Korrekturen sind dort willkommen; Fehler in der Runtime selbst bitte hier melden).

smolvm ist die Open-Source-Runtime hinter [smol machines](https://smolmachines.com) und steht in keiner Verbindung zu anderen Projekten namens SmolVM.

Diese Übersetzung entspricht möglicherweise nicht dem aktuellen Stand des [englischen Originals](../../README.md); bei Abweichungen ist die englische Version maßgeblich.

[Apache-2.0](../../LICENSE) · entwickelt von [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
