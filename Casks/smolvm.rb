cask "smolvm" do
  version "0.5.20"
  sha256 "92d687486852f78ea5ddf12be88c879ae9b8d8fc2bd7159de6586df0cb71d3e1"

  url "https://github.com/smol-machines/smolvm/releases/download/v#{version}/smolvm-#{version}-darwin-arm64.tar.gz"
  name "smolvm"
  desc "OCI-native microVM runtime with sub-200ms boot"
  homepage "https://github.com/smol-machines/smolvm"

  depends_on arch: :arm64
  depends_on macos: ">= :big_sur"

  binary "smolvm"

  caveats <<~EOS
    smolvm needs the agent rootfs at:
      ~/Library/Application Support/smolvm/agent-rootfs

    The runtime does not follow symlinks for that directory, so copy it on
    first install (the staged files live in the Caskroom):

      mkdir -p "$HOME/Library/Application Support/smolvm"
      cp -a "#{staged_path}/agent-rootfs" "$HOME/Library/Application Support/smolvm/"

    smolvm requires macOS 11 or later and Hypervisor.framework access.
  EOS
end
