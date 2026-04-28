class Smolvm < Formula
  desc "OCI-native microVM runtime with sub-200ms boot"
  homepage "https://github.com/smol-machines/smolvm"
  version "0.5.20"
  license "Apache-2.0"

  if OS.mac?
    odie "smolvm currently ships an Apple Silicon build only" if Hardware::CPU.intel?
    url "https://github.com/smol-machines/smolvm/releases/download/v#{version}/smolvm-#{version}-darwin-arm64.tar.gz"
    sha256 "92d687486852f78ea5ddf12be88c879ae9b8d8fc2bd7159de6586df0cb71d3e1"
  else
    odie "smolvm currently ships a Linux x86_64 build only" if Hardware::CPU.arm?
    url "https://github.com/smol-machines/smolvm/releases/download/v#{version}/smolvm-#{version}-linux-x86_64.tar.gz"
    sha256 "68431f36711c27dbb989e9ca55f42188a5788faab95a965a3f126481248efc1a"
  end

  depends_on "e2fsprogs"

  def install
    libexec.install Dir["*"]

    # The wrapper script in libexec/ resolves symlinks so a bin/ symlink works.
    bin.install_symlink libexec/"smolvm"
  end

  def caveats
    on_macos do
      <<~EOS
        smolvm needs the agent rootfs at:
          ~/Library/Application Support/smolvm/agent-rootfs

        The runtime does not follow symlinks for that directory, so copy it on
        first install:

          mkdir -p "$HOME/Library/Application Support/smolvm"
          cp -a "#{libexec}/agent-rootfs" "$HOME/Library/Application Support/smolvm/"

        smolvm requires macOS 11 or later and Hypervisor.framework access.
      EOS
    end
    on_linux do
      <<~EOS
        smolvm needs the agent rootfs at:
          ${XDG_DATA_HOME:-$HOME/.local/share}/smolvm/agent-rootfs

        Copy it on first install:

          DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/smolvm"
          mkdir -p "$DATA_DIR"
          cp -a "#{libexec}/agent-rootfs" "$DATA_DIR/"

        smolvm needs /dev/kvm. Make sure your user is in the kvm group:
          sudo usermod -aG kvm $USER  # then log out / log back in
      EOS
    end
  end

  test do
    assert_match "smolvm", shell_output("#{bin}/smolvm --version")
  end
end
