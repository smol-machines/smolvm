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
  <sub><a href="../../README.md">English</a> · <a href="README.zh-CN.md">中文</a> · <b>日本語</b> · <a href="README.ko.md">한국어</a> · <a href="README.ru.md">Русский</a> · <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a></sub>
</p>

smolvm
======

**AI エージェントのための、ブランチできるマイクロ VM。**
軽量な仮想マシンをソフトウェアに組み込み、持ち運べる開発環境やローカルのサンドボックスとして使えます。

インストール
------------

```bash
brew install smol-machines/tap/smolvm                  # macOS (Homebrew)
curl -sSL https://smolmachines.com/install.sh | bash   # macOS + Linux
```

Windows：`windows-x86_64` の[リリース](https://github.com/smol-machines/smolvm/releases)を展開し、`smolvm.exe` を実行します（[Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/) が必要です）。コーディングエージェント向け：インストール後に `smolvm --help` を実行すると、すべてのコマンドを確認できます。

人とエージェントのためのドキュメントは [`docs/`](../README.md) にあり、タスクごとに 1 フォルダです。事実をまとめた `README.md` と、エージェントがそのまま実行できる `SKILL.md`（スクリプト付き）が、各機能のリファレンスページと並んでいます。

クイックスタート
----------------

```bash
smolvm machine run --net --image alpine -- uname -a          # one-off VM, removed on exit
smolvm machine run --net -it --image alpine -- /bin/sh       # interactive shell
```

ローカル
--------

独自のカーネルを持つ本物の VM を、ノート PC や自分のサーバーで無料で動かせます。起動は 1 秒未満で、メモリは伸縮するため、ホストはゲストが実際に使う分だけを確保します。マシンは再起動後も残り、ローカルでビルドしたものも含め、どんな OCI イメージでも使えます。

```bash
smolvm machine create --net --name dev && smolvm machine start --name dev
smolvm machine exec --name dev -- apk add git
docker save myapp | smolvm machine run --image - -- ./app    # local image, no registry
```

マシンは [Smolfile](../smolfile.md) で宣言できます。イメージ、リソース、ポート、マウント、ネットワークポリシーを、リポジトリに置く 1 つのファイルにまとめられます。

組み込み
--------

ひとつの `Machine` API で、自分のコードからマシンを操作できます。SDK はデーモンなしでプロセス内で動き、ローカルでも [smol cloud](https://smolmachines.com) でも使えます。

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

ソースとドキュメント：[smol-machines/smol](https://github.com/smol-machines/smol) · [smolmachines.com/docs/sdk](https://smolmachines.com/docs/sdk)

ブランチ
--------

実行中のマシンを途中の状態のまま保存し、巻き戻したり、同じ時点から動き続けるコピーへブランチしたりできます。チェックポイントは RAM、CPU の状態、ディスクを保存し、ブランチは実行中のマシンのコピーオンライトの子です。

```bash
smolvm machine create --net --name agent --image alpine
smolvm machine start --name agent --branchable
smolvm machine branch --from agent --name try-1                   # live copy-on-write child
smolvm machine checkpoint --name agent -o agent.checkpoint        # save it, processes and all
smolvm machine create --name agent2 --from agent.checkpoint       # resume later or elsewhere
```

`--from <checkpoint> --at '~N'` で以前の世代に巻き戻せます（`machine checkpoint-log` を参照）。[一時停止と再開](../pause-resume.md)を使えば、実行状態を失わずに止められます。arm64 の Mac で取ったチェックポイントは arm64 の Linux で再開できます。[実行中のマシンを Mac から Linux へ移す](../mac-to-linux.md)を参照してください。詳しくは[ブランチ](../branching.md)と[増分チェックポイント](../incremental-checkpoints.md)へ。

ポータブル
----------

どう構成したマシンでも、1 つの `.smolmachine` ファイルにまとめられます。任意の OCI レジストリにプッシュするか、自己完結した実行ファイルとして動かせます。インストール不要で、200 ms 未満で起動します。

```bash
smolvm machine stop --name dev && smolvm pack create --from-vm dev -o dev
smolvm pack push --file dev.smolmachine ghcr.io/you/dev:v1
smolvm pack create --image python:3.12-alpine -o ./python312
./python312 run -- python3 --version
```

チェックポイントも持ち運べます。別のホストや smol cloud で復元できます。

安全
----

各ワークロードには、独自のカーネルを持つハードウェア分離された VM が割り当てられます。ネットワークは既定でオフ、外向きの通信は指定したホストに限定でき、コードは資格情報を一度も読まずに使えます。

安全は共同の責任です。smolvm は境界を提供します。ワークロードごとに別々の VM とカーネルがあり、許可しない限り何もホストに届きません。その境界を何が越えるかは、あなたが決めます。マウントするフォルダ、開くポート、許可するホスト、転送するシークレットや SSH エージェントは、すべてワークロードが使えるものになります。信頼できないワークロードには、必要なものだけを渡してください。

```bash
smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- wget -qO- https://google.com   # blocked
smolvm machine run --net --image alpine --allow-host-pattern registry.npmjs.org -- wget -qO- https://registry.npmjs.org   # exact host only
NOTION_API_KEY=secret_… smolvm machine run --net --image alpine \
  --credential notion=NOTION_API_KEY@api.notion.com -- sh -c 'echo $NOTION_API_KEY'   # a placeholder
```

[資格情報の置換](../credential-substitution.md)と[セキュリティモデル](../security-model.md)を参照してください。
サブドメインだけを許可するには `--allow-host-pattern '*.example.com'` を使います。`--allow-host example.com` はドメインそのものとそのサブドメインを許可します。`smolvm machine update` はエントリの追加（`--allow-host`、`--allow-host-pattern`、`--allow-cidr`）と削除（`--remove-allow-host` には追加したときのホストまたはパターンを指定、`--remove-allow-cidr`）ができ、許可リスト付きで起動した実行中のマシンにも使えます。許可は次の接続や名前解決から有効になり、削除したホストについて学習済みのアドレスも一緒に消えます。

しくみ
------

各ワークロードは、独自のゲストカーネルを持つハードウェア仮想化された VM で動きます。基盤は [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor)（macOS）、KVM（Linux）、[Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/)（Windows）です。VMM は [libkrun](https://github.com/containers/libkrun)、ゲストカーネルは [libkrunfw](https://github.com/smol-machines/libkrunfw) が提供します。イメージは [OCI](https://opencontainers.org/) 形式なので、Docker Hub や ghcr.io などにあるイメージは、Docker デーモンなしでそのままマイクロ VM として起動します。

既定値：4 vCPU、8 GiB RAM。メモリは virtio balloon で伸縮し、アイドル中の vCPU はハイパーバイザー内で休止するため、多めに割り当ててもほとんどコストがかかりません。`--cpus` と `--mem` で変更できます。

比較
----

|                     | smolvm | コンテナ | Colima | QEMU | Firecracker | Kata |
|---------------------|--------|----------|--------|------|-------------|------|
| ワークロードの境界  | VM + ゲストカーネル | 名前空間 + 共有カーネル | 共有 VM 内の名前空間 | VM + ゲストカーネル | VM + ゲストカーネル | コンテナごとに VM |
| 起動時間            | エージェント準備完了まで 200ms 未満 | ~100ms | 数秒 | ~15-30s | <125ms | ~500ms |
| アーキテクチャ      | ライブラリ（libkrun） | デーモン | デーモン（VM 内） | プロセス | プロセス | ランタイムスタック |
| ワークロードごとの VM | あり | なし | なし（共有） | あり | あり | あり |
| macOS ネイティブ    | はい | Docker VM 経由 | はい（krunkit） | はい | いいえ | いいえ |
| 組み込み SDK        | あり | なし | なし | なし | なし | なし |
| ポータブルな成果物  | `.smolmachine` | イメージ（デーモンが必要） | なし | なし | なし | なし |

対応プラットフォーム
--------------------

| ホスト | ゲスト | 要件 |
|--------|--------|------|
| macOS Apple Silicon | arm64 Linux | macOS 11+ |
| macOS Intel | x86_64 Linux | リリースビルドは未公開、未検証 |
| Linux x86_64 | x86_64 Linux | KVM（`/dev/kvm`） |
| Linux aarch64 | aarch64 Linux | KVM（`/dev/kvm`） |
| Windows x86_64 | x86_64 Linux | Windows Hypervisor Platform（WHP）が有効 |

Windows はポータブルなチェックポイント、一時停止と再開、`--freeze-source` を使ったブランチに対応しています。GPU アクセラレーションはまだ使えません。[既知の制限](../limitations.md)を参照してください。

その他
------

* [Kubernetes](../kubernetes.md)：`RuntimeClass` を通して Pod をマイクロ VM として動かします。
* [GPU と CUDA](../gpu.md)：virtio-gpu / Venus による Vulkan と、CUDA API リモーティング。
* [サンプル](../../examples/)：python、node、docker-in-vm、local-llm、headless-browser、doom。
* [開発](../DEVELOPMENT.md) · ユーザー向けドキュメントは [smolmachines.com/docs](https://smolmachines.com/docs/) にあり、[smol-machines/docs](https://github.com/smol-machines/docs) で書かれています（修正はそちらへ。ランタイムのバグはこのリポジトリへ）。

smolvm は [smol machines](https://smolmachines.com) を支えるオープンソースのランタイムで、SmolVM という名前のほかのプロジェクトとは関係ありません。

この翻訳は[英語版](../../README.md)より古い場合があります。内容が異なるときは英語版が正です。

[Apache-2.0](../../LICENSE) · 作者 [@binsquare](https://github.com/BinSquare) · [twitter](https://x.com/binsquares) · [github](https://github.com/smol-machines/smolvm)
