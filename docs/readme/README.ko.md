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
  <sub><a href="../../README.md">English</a> · <a href="README.zh-CN.md">中文</a> · <a href="README.ja.md">日本語</a> · <b>한국어</b> · <a href="README.ru.md">Русский</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a></sub>
</p>

smolvm
======

**AI 에이전트를 위한, 브랜치할 수 있는 마이크로 VM.**
가벼운 가상 머신을 소프트웨어에 내장해, 이식 가능한 개발 환경과 로컬 샌드박스로 쓰세요.

설치
----

```bash
brew install smol-machines/tap/smolvm                  # macOS (Homebrew)
curl -sSL https://smolmachines.com/install.sh | bash   # macOS + Linux
```

Windows: `windows-x86_64` [릴리스](https://github.com/smol-machines/smolvm/releases)의 압축을 풀고 `smolvm.exe`를 실행하세요([Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)이 필요합니다). 코딩 에이전트: 설치한 뒤 `smolvm --help`를 실행하면 모든 명령을 확인할 수 있습니다.

사람과 에이전트를 위한 문서는 [`docs/`](../README.md)에 있으며, 작업마다 폴더가 하나씩 있습니다. 사실을 정리한 `README.md`와 에이전트가 그대로 따라 할 수 있는 `SKILL.md`(스크립트 포함)가 각 기능의 참고 문서 옆에 있습니다.

빠른 시작
---------

```bash
smolvm machine run --net --image alpine -- uname -a          # one-off VM, removed on exit
smolvm machine run --net -it --image alpine -- /bin/sh       # interactive shell
```

로컬
----

자체 커널을 가진 진짜 VM을 노트북이나 자신의 서버에서 무료로 실행하세요. 1초 안에 부팅되고 메모리는 탄력적이라, 호스트는 게스트가 실제로 쓰는 만큼만 할당합니다. 머신은 재시작해도 유지되며, 로컬에서 빌드한 이미지를 포함해 어떤 OCI 이미지든 쓸 수 있습니다.

```bash
smolvm machine create --net --name dev && smolvm machine start --name dev
smolvm machine exec --name dev -- apk add git
docker save myapp | smolvm machine run --image - -- ./app    # local image, no registry
```

[Smolfile](../smolfile.md)로 머신을 선언하세요. 이미지, 리소스, 포트, 마운트, 네트워크 정책을 저장소에 넣는 파일 하나에 담을 수 있습니다.

내장형
------

하나의 `Machine` API로 내 코드에서 머신을 다룹니다. SDK는 데몬 없이 내 프로세스 안에서 실행되며, 로컬에서도 [smol cloud](https://smolmachines.com)에서도 동작합니다.

```bash
npm install smolmachines     # Node / TypeScript
pip install smolmachines     # Python
cargo add smolmachines       # Rust
```

```ts
import { Machine } from 'smolmachines';

const m = await Machine.create({ image: 'python:3.12-alpine', network: true });
const r = await m.exec(['python3', '-c', 'print(2 ** 10)']);
console.log(r.stdout); // 1024
await m.delete();
```

소스와 문서: [smol-machines/smol](https://github.com/smol-machines/smol) · [smolmachines.com/docs/sdk](https://smolmachines.com/docs/sdk)

브랜치
------

실행 중인 머신을 도중 상태 그대로 저장하고, 되감거나, 같은 시점부터 계속 실행되는 복사본으로 브랜치할 수 있습니다. 체크포인트는 RAM, CPU 상태, 디스크를 저장하고, 브랜치는 실행 중인 머신의 copy-on-write 자식입니다.

```bash
smolvm machine create --net --name agent --image alpine
smolvm machine start --name agent --branchable
smolvm machine branch --from agent --name try-1                   # live copy-on-write child
smolvm machine checkpoint --name agent -o agent.checkpoint        # save it, processes and all
smolvm machine create --name agent2 --from agent.checkpoint       # resume later or elsewhere
```

`--from <checkpoint> --at '~N'`으로 이전 세대로 되감을 수 있고(`machine checkpoint-log` 참고), [일시 정지와 재개](../pause-resume.md)로 실행 상태를 잃지 않고 멈출 수 있습니다. arm64 Mac에서 만든 체크포인트는 arm64 Linux에서 재개됩니다. [실행 중인 머신을 Mac에서 Linux로 옮기기](../mac-to-linux.md)를 참고하세요. 자세한 내용은 [브랜치](../branching.md)와 [증분 체크포인트](../incremental-checkpoints.md)에 있습니다.

이식성
------

어떻게 구성한 머신이든 `.smolmachine` 파일 하나로 묶을 수 있습니다. 어떤 OCI 레지스트리에든 푸시하거나, 설치할 것 없이 200ms 안에 부팅되는 독립 실행 파일로 실행하세요.

```bash
smolvm machine stop --name dev && smolvm pack create --from-vm dev -o dev
smolvm pack push --file dev.smolmachine ghcr.io/you/dev:v1
smolvm pack create --image python:3.12-alpine -o ./python312
./python312 run -- python3 --version
```

체크포인트도 이식할 수 있습니다. 다른 호스트나 smol cloud에서 복원하세요.

안전
----

모든 워크로드는 자체 커널을 가진, 하드웨어로 격리된 VM에서 실행됩니다. 네트워크는 기본적으로 꺼져 있고, 외부로 나가는 통신은 지정한 호스트로 제한할 수 있으며, 코드는 자격 증명을 한 번도 읽지 않고 사용할 수 있습니다.

안전은 공동의 책임입니다. smolvm은 경계를 제공합니다. 워크로드마다 별도의 VM과 커널이 있고, 허용하지 않으면 아무것도 호스트에 닿지 않습니다. 그 경계를 무엇이 넘을지는 당신이 정합니다. 마운트하는 폴더, 여는 포트, 허용하는 호스트, 전달하는 시크릿이나 SSH 에이전트는 모두 워크로드가 쓸 수 있게 되므로, 신뢰할 수 없는 워크로드에는 꼭 필요한 것만 주세요.

```bash
smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -qO- https://google.com   # blocked
smolvm machine run --net --image alpine --allow-host-pattern registry.npmjs.org -- wget -qO- https://registry.npmjs.org   # exact host only
NOTION_API_KEY=secret_… smolvm machine run --net --image alpine \
  --credential notion=NOTION_API_KEY@api.notion.com -- sh -c 'echo $NOTION_API_KEY'   # a placeholder
```

[자격 증명 치환](../credential-substitution.md)과 [보안 모델](../security-model.md)을 참고하세요.
하위 도메인만 허용하려면 `--allow-host-pattern '*.example.com'`을 쓰고, `--allow-host example.com`은 도메인 자체와 그 하위 도메인을 허용합니다. `smolvm machine update`로 항목을 추가(`--allow-host`, `--allow-host-pattern`, `--allow-cidr`)하고 제거(`--remove-allow-host`에는 추가할 때의 호스트나 패턴을 그대로, `--remove-allow-cidr`)할 수 있으며, 허용 목록으로 시작해 실행 중인 머신에도 적용됩니다. 허용은 다음 연결이나 조회부터 적용되고, 제거한 호스트에 대해 학습된 주소도 함께 사라집니다.

동작 방식
---------

모든 워크로드는 자체 게스트 커널을 가진 하드웨어 가상화 VM에서 실행되며, [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor)(macOS), KVM(Linux), [Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)(Windows) 위에서 동작합니다. VMM은 [libkrun](https://github.com/containers/libkrun)이고, 게스트 커널은 [libkrunfw](https://github.com/smol-machines/libkrunfw)가 제공합니다. 이미지는 [OCI](https://opencontainers.org/) 형식이라, Docker Hub나 ghcr.io 등 어느 레지스트리의 이미지든 Docker 데몬 없이 마이크로 VM으로 부팅됩니다.

기본값: vCPU 4개, RAM 8 GiB. 메모리는 virtio balloon으로 늘었다 줄었다 하고, 쉬고 있는 vCPU는 하이퍼바이저 안에서 잠들기 때문에 넉넉하게 할당해도 비용이 거의 들지 않습니다. `--cpus`와 `--mem`으로 바꿀 수 있습니다.

비교
----

|                     | smolvm | 컨테이너 | Colima | QEMU | Firecracker | Kata |
|---------------------|--------|----------|--------|------|-------------|------|
| 워크로드 경계       | VM + 게스트 커널 | 네임스페이스 + 공유 커널 | 공유 VM 안의 네임스페이스 | VM + 게스트 커널 | VM + 게스트 커널 | 컨테이너마다 VM |
| 부팅 시간           | 에이전트 준비까지 200ms 미만 | ~100ms | 수 초 | ~15-30s | <125ms | ~500ms |
| 아키텍처            | 라이브러리(libkrun) | 데몬 | 데몬(VM 안) | 프로세스 | 프로세스 | 런타임 스택 |
| 워크로드별 VM       | 예 | 아니요 | 아니요(공유) | 예 | 예 | 예 |
| macOS 네이티브      | 예 | Docker VM 경유 | 예(krunkit) | 예 | 아니요 | 아니요 |
| 내장 SDK            | 예 | 아니요 | 아니요 | 아니요 | 아니요 | 아니요 |
| 이식 가능한 산출물  | `.smolmachine` | 이미지(데몬 필요) | 아니요 | 아니요 | 아니요 | 아니요 |

지원 플랫폼
-----------

| 호스트 | 게스트 | 요구 사항 |
|--------|--------|-----------|
| macOS Apple Silicon | arm64 Linux | macOS 11+ |
| macOS Intel | x86_64 Linux | 릴리스 빌드 미공개, 테스트되지 않음 |
| Linux x86_64 | x86_64 Linux | KVM(`/dev/kvm`) |
| Linux aarch64 | aarch64 Linux | KVM(`/dev/kvm`) |
| Windows x86_64 | x86_64 Linux | Windows Hypervisor Platform(WHP) 활성화 |

Windows는 이식 가능한 체크포인트, 일시 정지와 재개, `--freeze-source`를 이용한 브랜치를 지원합니다. GPU 가속은 아직 쓸 수 없습니다. [알려진 제한 사항](../limitations.md)을 참고하세요.

더 보기
-------

* [Kubernetes](../kubernetes.md): `RuntimeClass`로 Pod를 마이크로 VM으로 실행합니다.
* [GPU와 CUDA](../gpu.md): virtio-gpu / Venus를 통한 Vulkan과 CUDA API 원격 호출.
* [예제](../../examples/): python, node, docker-in-vm, local-llm, headless-browser, doom.
* [개발](../DEVELOPMENT.md) · 사용자 문서는 [smolmachines.com/docs](https://smolmachines.com/docs/)에 있고 [smol-machines/docs](https://github.com/smol-machines/docs)에서 작성됩니다(수정은 그쪽으로, 런타임 버그는 이 저장소로).

smolvm은 [smol machines](https://smolmachines.com)를 움직이는 오픈 소스 런타임이며, SmolVM이라는 이름의 다른 프로젝트와는 관련이 없습니다.

이 번역은 [영어 원문](../../README.md)보다 오래되었을 수 있습니다. 내용이 다르면 영어판이 기준입니다.

[Apache-2.0](../../LICENSE) · 만든 사람 [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
