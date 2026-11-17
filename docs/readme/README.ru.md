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
  <sub><a href="../../README.md">English</a> · <a href="README.zh-CN.md">中文</a> · <a href="README.ja.md">日本語</a> · <a href="README.ko.md">한국어</a> · <b>Русский</b> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a></sub>
</p>

smolvm
======

**microVM с поддержкой ветвления для ИИ-агентов.**
Встраивайте легковесные виртуальные машины в своё ПО, используйте их для переносимых сред разработки и локальной изоляции в песочнице.

Установка
-------

```bash
brew install smol-machines/tap/smolvm                  # macOS (Homebrew)
curl -sSL https://smolmachines.com/install.sh | bash   # macOS + Linux
```

Windows: распакуйте архив `windows-x86_64` из [релиза](https://github.com/smol-machines/smolvm/releases) и запустите `smolvm.exe` (требуется [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)). ИИ-агенты для написания кода: после установки выполните `smolvm --help`, чтобы узнать обо всех командах.

Документация для людей и агентов находится в [`docs/`](../README.md): каждой задаче отведена отдельная папка с файлом `README.md`, содержащим сведения, файлом `SKILL.md`, инструкциям которого может следовать агент, и сопутствующими скриптами; рядом расположены справочные страницы по каждой функции.

Быстрый старт
-----------

```bash
smolvm machine run --net --image alpine -- uname -a          # one-off VM, removed on exit
smolvm machine run --net -it --image alpine -- /bin/sh       # interactive shell
```

Локальное использование
-----

Полноценные виртуальные машины с собственным ядром бесплатно работают на вашем ноутбуке или ваших серверах. Они загружаются менее чем за секунду, а объём памяти меняется динамически, поэтому хост выделяет только ту память, которую использует гостевая система. Машины сохраняются между перезапусками; подходит любой OCI-образ, в том числе собранный локально.

```bash
smolvm machine create --net --name dev && smolvm machine start --name dev
smolvm machine exec --name dev -- apk add git
docker save myapp | smolvm machine run --image - -- ./app    # local image, no registry
```

Смонтируйте бакет S3, R2 или MinIO с помощью `-v s3://bucket/prefix:/data`; см. [документацию по томам](../volumes.md).

Опишите машину в [Smolfile](../smolfile.md): образ, ресурсы, порты, точки монтирования и сетевая политика в одном файле под контролем версий.

Встраивание
----------

Управляйте машинами из своего кода через единый API `Machine`. SDK работают в вашем процессе без демона, локально или в [smol cloud](https://smolmachines.com).

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

Исходный код и документация: [smol-machines/smol](https://github.com/smol-machines/smol) · [smolmachines.com/docs/sdk](https://smolmachines.com/docs/sdk)

Ветвление
----------

Сохраняйте работающую машину в ходе выполнения, возвращайте её к прежнему состоянию или создавайте ответвления: копии, которые продолжают работу с одной и той же точки. Контрольные точки сохраняют оперативную память, состояние процессора и диски; ответвления — дочерние копии работающей машины с копированием при записи (copy-on-write).

```bash
smolvm machine create --net --name agent --image alpine
smolvm machine start --name agent --branchable
smolvm machine branch --from agent --name try-1                   # live copy-on-write child
smolvm machine checkpoint --name agent -o agent.checkpoint        # save it, processes and all
smolvm machine create --name agent2 --from agent.checkpoint       # resume later or elsewhere
```

Вернитесь к более раннему поколению с помощью `--from <checkpoint> --at '~N'` (см. `machine checkpoint-log`), а чтобы остановить машину, не потеряв состояние выполнения, используйте [приостановку и возобновление](../pause-resume.md). Контрольную точку, созданную на Mac с arm64, можно восстановить в Linux с arm64; см. [Перенос работающей машины с Mac на Linux](../mac-to-linux.md). Подробнее о [ветвлении](../branching.md) и [инкрементальных контрольных точках](../incremental-checkpoints.md).

Переносимость
--------

Упакуйте машину, как бы она ни была настроена, в один файл `.smolmachine`. Отправьте его в любой OCI-реестр или запустите как самодостаточный исполняемый файл, который загружается менее чем за 200 мс и не требует никакой установки.

```bash
smolvm machine stop --name dev && smolvm pack create --from-vm dev -o dev
smolvm pack push --file dev.smolmachine ghcr.io/you/dev:v1
smolvm pack create --image python:3.12-alpine -o ./python312
./python312 run -- python3 --version
```

Контрольные точки тоже переносимы: их можно восстановить на другом хосте или в smol cloud.

Безопасность
----

Каждая рабочая нагрузка получает виртуальную машину с аппаратной изоляцией и собственным ядром. По умолчанию сеть отключена, исходящий трафик можно ограничить указанными хостами, а код может использовать учётные данные без доступа к их содержимому.

Безопасность — общая ответственность. smolvm обеспечивает границу изоляции: отдельную виртуальную машину и ядро для каждой рабочей нагрузки; без вашего разрешения ничто не получает доступ к хосту. Что может пересекать эту границу, решаете вы. Каждая смонтированная вами папка, открытый порт, разрешённый хост, переданный секрет или перенаправленный SSH-агент становятся доступны рабочей нагрузке, поэтому предоставляйте недоверенной рабочей нагрузке только необходимое.

```bash
smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -qO- https://google.com   # blocked
smolvm machine run --net --image alpine --allow-host-pattern registry.npmjs.org -- wget -qO- https://registry.npmjs.org   # exact host only
NOTION_API_KEY=secret_… smolvm machine run --net --image alpine \
  --credential notion=NOTION_API_KEY@api.notion.com -- sh -c 'echo $NOTION_API_KEY'   # a placeholder
```

См. [подстановку учётных данных](../credential-substitution.md) и [модель безопасности](../security-model.md).
Используйте `--allow-host-pattern '*.example.com'`, чтобы разрешить только поддомены; `--allow-host example.com` разрешает сам домен и
его поддомены. Команда `smolvm machine update` добавляет (`--allow-host`, `--allow-host-pattern`, `--allow-cidr`) и удаляет
(`--remove-allow-host`, хост или шаблон в том виде, в котором он был добавлен; `--remove-allow-cidr`) записи, в том числе у работающей машины,
запущенной со списком разрешений: новое разрешение действует со следующего подключения или DNS-запроса, а при удалении хоста удаляются и ранее полученные для него адреса.

Принцип работы
------------

Каждая рабочая нагрузка выполняется в виртуальной машине с аппаратной виртуализацией и собственным гостевым ядром на базе [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (macOS), KVM (Linux) или [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/) (Windows). [libkrun](https://github.com/containers/libkrun) служит монитором виртуальных машин (VMM), а [libkrunfw](https://github.com/smol-machines/libkrunfw) предоставляет гостевое ядро. Образы используют формат [OCI](https://opencontainers.org/), поэтому любой образ из Docker Hub, ghcr.io или другого реестра запускается как microVM без Docker-демона.

По умолчанию: 4 vCPU и 8 ГиБ оперативной памяти. Объём памяти меняется динамически с помощью virtio balloon, а неактивные vCPU переходят в спящий режим в гипервизоре, поэтому выделение ресурсов с запасом почти ничего не стоит. Переопределить их можно с помощью `--cpus` и `--mem`.

Сравнение
----------

|                     | smolvm | Контейнеры | Colima | QEMU | Firecracker | Kata |
|---------------------|--------|------------|--------|------|-------------|------|
| Граница изоляции рабочей нагрузки | VM + гостевое ядро | Пространство имён + общее ядро | Пространство имён внутри общей VM | VM + гостевое ядро | VM + гостевое ядро | VM на каждый контейнер |
| Время загрузки | <200ms до готовности гостевого агента smolvm | ~100ms | ~несколько секунд | ~15-30s | <125ms | ~500ms |
| Архитектура | Библиотека (libkrun) | Демон | Демон (в VM) | Процесс | Процесс | Стек среды выполнения |
| Отдельная VM для каждой рабочей нагрузки | Да | Нет | Нет (общая) | Да | Да | Да |
| Нативная поддержка macOS | Да | Через VM Docker | Да (krunkit) | Да | Нет | Нет |
| Встраиваемый SDK | Да | Нет | Нет | Нет | Нет | Нет |
| Переносимые артефакты | `.smolmachine` | Образы (нужен демон) | Нет | Нет | Нет | Нет |

Поддержка платформ
----------------

| Хост | Гостевая система | Требования |
|------|-------|-------------|
| macOS Apple Silicon | arm64 Linux | macOS 11+ |
| macOS Intel | x86_64 Linux | релизная сборка не опубликована; тестирование не проводилось |
| Linux x86_64 | x86_64 Linux | KVM (`/dev/kvm`) |
| Linux aarch64 | aarch64 Linux | KVM (`/dev/kvm`) |
| Windows x86_64 | x86_64 Linux | включена Windows Hypervisor Platform (WHP) |

Windows поддерживает переносимые контрольные точки, приостановку и возобновление, а также ответвления с `--freeze-source`. Ускорение на GPU по-прежнему недоступно; см. [известные ограничения](../limitations.md).

Дополнительно
----

* [Kubernetes](../kubernetes.md): запускайте Pod'ы как microVM с помощью `RuntimeClass`.
* [GPU и CUDA](../gpu.md): Vulkan через virtio-gpu / Venus и удалённые вызовы CUDA API.
* [Именованные сети](../named-networks.md): машины, которые могут обращаться друг к другу по IP.
* [Вложенная виртуализация](../nested-virtualization.md): запускайте KVM, smolvm или QEMU внутри машины.
* [Отображение в браузере](../browser-display.md): рабочий стол машины в браузере с поддержкой клавиатуры и мыши.
* [Примеры](../../examples/): python, node, docker-in-vm, local-llm, headless-browser, doom.
* [Разработка](../DEVELOPMENT.md) · Документация для пользователей на [smolmachines.com/docs](https://smolmachines.com/docs/), её исходные файлы находятся в [smol-machines/docs](https://github.com/smol-machines/docs) (исправления в том репозитории приветствуются; об ошибках в самой среде выполнения сообщайте здесь).

smolvm — среда выполнения с открытым исходным кодом, лежащая в основе [smol machines](https://smolmachines.com) и не связанная с другими проектами под названием SmolVM.

Этот перевод может отставать от [английского оригинала](../../README.md); в случае расхождений английская версия имеет приоритет.

[Apache-2.0](../../LICENSE) · автор [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
