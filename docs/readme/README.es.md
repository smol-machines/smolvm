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
  <sub><a href="../../README.md">English</a> · <a href="README.zh-CN.md">中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <a href="README.ru.md">Русский</a> · <b>Español</b> · <a href="README.de.md">Deutsch</a></sub>
</p>

smolvm
======

**microVM ramificables para agentes de IA.**
Integra máquinas virtuales ligeras en tu software y úsalas como entornos de desarrollo portables y como sandbox local.

Instalación
-----------

```bash
brew install smol-machines/tap/smolvm                  # macOS (Homebrew)
curl -sSL https://smolmachines.com/install.sh | bash   # macOS + Linux
```

Windows: descomprime el archivo `windows-x86_64` de la [versión publicada](https://github.com/smol-machines/smolvm/releases) y ejecuta `smolvm.exe` (requiere [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)). Agentes de programación: ejecuten `smolvm --help` después de la instalación para conocer todos los comandos.

La documentación para personas y agentes está en [`docs/`](../README.md), con una carpeta por tarea: un `README.md` con la información y un `SKILL.md` que un agente puede seguir, con sus scripts, junto a la página de referencia de cada función.

Inicio rápido
-------------

```bash
smolvm machine run --net --image alpine -- uname -a          # one-off VM, removed on exit
smolvm machine run --net -it --image alpine -- /bin/sh       # interactive shell
```

Local
-----

VM reales con su propio kernel, gratuitas en tu equipo portátil o en tus propios servidores. Arrancan en menos de un segundo y la memoria es elástica, por lo que el host solo asigna la memoria que usa el sistema invitado. Las máquinas persisten entre reinicios y funcionan con cualquier imagen OCI, incluidas las que construyas localmente.

```bash
smolvm machine create --net --name dev && smolvm machine start --name dev
smolvm machine exec --name dev -- apk add git
docker save myapp | smolvm machine run --image - -- ./app    # local image, no registry
```

Monta un bucket de S3, R2 o MinIO con `-v s3://bucket/prefix:/data`; consulta [volúmenes](../volumes.md).

Declara una máquina en un [Smolfile](../smolfile.md): imagen, recursos, puertos, montajes y política de red en un único archivo bajo control de versiones.

Integrable
----------

Controla las máquinas desde tu propio código con una única API `Machine`. Los SDK se ejecutan dentro de tu proceso sin ningún daemon, en local o en [smol cloud](https://smolmachines.com).

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

Código fuente y documentación: [smol-machines/smol](https://github.com/smol-machines/smol) · [smolmachines.com/docs/sdk](https://smolmachines.com/docs/sdk)

Ramificable
-----------

Guarda una máquina en plena ejecución, devuélvela a un estado anterior o ramifícala en copias que siguen ejecutándose desde el mismo punto. Los puntos de control capturan la RAM, el estado de la CPU y los discos; las ramas son máquinas hijas de una máquina en ejecución y usan copy-on-write.

```bash
smolvm machine create --net --name agent --image alpine
smolvm machine start --name agent --branchable
smolvm machine branch --from agent --name try-1                   # live copy-on-write child
smolvm machine checkpoint --name agent -o agent.checkpoint        # save it, processes and all
smolvm machine create --name agent2 --from agent.checkpoint       # resume later or elsewhere
```

Vuelve a una generación anterior con `--from <checkpoint> --at '~N'` (consulta `machine checkpoint-log`) y usa [pausa y reanudación](../pause-resume.md) para detener la máquina sin perder el estado de ejecución. Un punto de control creado en un Mac arm64 permite reanudar la ejecución en Linux arm64; consulta [Trasladar una máquina en ejecución de un Mac a Linux](../mac-to-linux.md). Más información en [Ramificación](../branching.md) y [puntos de control incrementales](../incremental-checkpoints.md).

Portable
--------

Empaqueta una máquina, sea cual sea su configuración, en un único archivo `.smolmachine`. Súbelo a cualquier registro OCI o ejecútalo como un ejecutable autocontenido que arranca en menos de 200 ms sin tener que instalar nada.

```bash
smolvm machine stop --name dev && smolvm pack create --from-vm dev -o dev
smolvm pack push --file dev.smolmachine ghcr.io/you/dev:v1
smolvm pack create --image python:3.12-alpine -o ./python312
./python312 run -- python3 --version
```

Los puntos de control también son portables: restaura uno en otro host o en smol cloud.

Seguro
------

Cada carga de trabajo dispone de una VM con aislamiento por hardware y su propio kernel. La red está desactivada de forma predeterminada, el tráfico de salida puede limitarse a hosts especificados por nombre y el código puede usar una credencial sin llegar a leerla.

La seguridad es una responsabilidad compartida. smolvm proporciona el límite: una VM y un kernel independientes para cada carga de trabajo, sin que nada llegue al host a menos que lo permitas. Tú decides qué cruza ese límite. Cada carpeta que montas, puerto que abres, host que permites y secreto o agente SSH que reenvías se convierte en algo que la carga de trabajo puede usar, así que proporciona a una carga de trabajo no confiable solo lo que necesita.

```bash
smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -qO- https://google.com   # blocked
smolvm machine run --net --image alpine --allow-host-pattern registry.npmjs.org -- wget -qO- https://registry.npmjs.org   # exact host only
NOTION_API_KEY=secret_… smolvm machine run --net --image alpine \
  --credential notion=NOTION_API_KEY@api.notion.com -- sh -c 'echo $NOTION_API_KEY'   # a placeholder
```

Consulta [sustitución de credenciales](../credential-substitution.md) y el [modelo de seguridad](../security-model.md).
Usa `--allow-host-pattern '*.example.com'` para permitir solo subdominios; `--allow-host example.com` permite el propio dominio y
sus subdominios. `smolvm machine update` agrega (`--allow-host`, `--allow-host-pattern`, `--allow-cidr`) y elimina
(`--remove-allow-host`, con el host o patrón tal como se agregó; `--remove-allow-cidr`) entradas, también en una máquina en ejecución
iniciada con una lista de permitidos: un permiso se aplica a partir de la siguiente conexión o consulta DNS y, al eliminar un host, también se eliminan las direcciones aprendidas para él.

Cómo funciona
-------------

Cada carga de trabajo se ejecuta en una VM virtualizada por hardware con su propio kernel invitado sobre [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (macOS), KVM (Linux) o [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/) (Windows). [libkrun](https://github.com/containers/libkrun) es el VMM y [libkrunfw](https://github.com/smol-machines/libkrunfw) proporciona el kernel invitado. Las imágenes usan el formato [OCI](https://opencontainers.org/), por lo que cualquier imagen de Docker Hub, ghcr.io u otro registro arranca como una microVM, sin ningún daemon de Docker.

Valores predeterminados: 4 vCPU, 8 GiB de RAM. La memoria es elástica gracias a virtio balloon y las vCPU inactivas entran en reposo en el hipervisor, por lo que el sobreaprovisionamiento casi no tiene costo. Modifica estos valores con `--cpus` y `--mem`.

Comparación
-----------

|                     | smolvm | Contenedores | Colima | QEMU | Firecracker | Kata |
|---------------------|--------|------------|--------|------|-------------|------|
| Límite de la carga de trabajo | VM + kernel invitado | Espacio de nombres + kernel compartido | Espacio de nombres dentro de una VM compartida | VM + kernel invitado | VM + kernel invitado | VM por contenedor |
| Tiempo de arranque | Agente invitado de smolvm listo en <200ms | ~100ms | ~segundos | ~15-30s | <125ms | ~500ms |
| Arquitectura | Biblioteca (libkrun) | Daemon | Daemon (en una VM) | Proceso | Proceso | Pila de runtime |
| VM por carga de trabajo | Sí | No | No (compartida) | Sí | Sí | Sí |
| Nativo en macOS | Sí | Mediante una VM de Docker | Sí (krunkit) | Sí | No | No |
| SDK integrable | Sí | No | No | No | No | No |
| Artefactos portables | `.smolmachine` | Imágenes (necesitan un daemon) | No | No | No | No |

Plataformas compatibles
-----------------------

| Host | Invitado | Requisitos |
|------|-------|-------------|
| macOS Apple Silicon | arm64 Linux | macOS 11+ |
| macOS Intel | x86_64 Linux | no se ha publicado una compilación de lanzamiento; sin probar |
| Linux x86_64 | x86_64 Linux | KVM (`/dev/kvm`) |
| Linux aarch64 | aarch64 Linux | KVM (`/dev/kvm`) |
| Windows x86_64 | x86_64 Linux | Windows Hypervisor Platform (WHP) habilitada |

Windows admite puntos de control portables, pausa/reanudación y ramas con `--freeze-source`. La aceleración por GPU sigue sin estar disponible; consulta [limitaciones conocidas](../limitations.md).

Más
---

* [Kubernetes](../kubernetes.md): ejecuta los Pods como microVM mediante una `RuntimeClass`.
* [GPU y CUDA](../gpu.md): Vulkan mediante virtio-gpu / Venus y llamadas remotas a la API de CUDA.
* [Redes con nombre](../named-networks.md): máquinas que se comunican entre sí por IP.
* [Virtualización anidada](../nested-virtualization.md): ejecuta KVM, smolvm o QEMU dentro de una máquina.
* [Visualización en el navegador](../browser-display.md): el escritorio de una máquina en el navegador, con teclado y mouse.
* [Ejemplos](../../examples/): python, node, docker-in-vm, local-llm, headless-browser, doom.
* [Desarrollo](../DEVELOPMENT.md) · Documentación para usuarios en [smolmachines.com/docs](https://smolmachines.com/docs/), escrita en [smol-machines/docs](https://github.com/smol-machines/docs) (las correcciones son bienvenidas allí; los errores del runtime se notifican aquí).

smolvm es el runtime de código abierto en el que se basa [smol machines](https://smolmachines.com) y no está afiliado a otros proyectos llamados SmolVM.

Esta traducción puede estar desactualizada con respecto al [original en inglés](../../README.md); en caso de discrepancias, prevalece la versión en inglés.

[Apache-2.0](../../LICENSE) · creado por [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
