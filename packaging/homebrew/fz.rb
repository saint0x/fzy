class Fz < Formula
  desc "fzy compiler and deterministic validation CLI"
  homepage "https://github.com/saint0x/fzy"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/saint0x/fzy/releases/download/v#{version}/fz-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    else
      url "https://github.com/saint0x/fzy/releases/download/v#{version}/fz-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/saint0x/fzy/releases/download/v#{version}/fz-v#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    else
      url "https://github.com/saint0x/fzy/releases/download/v#{version}/fz-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  def install
    bin.install "fz"
    prefix.install "README.md"
    prefix.install "USAGE.md"
    prefix.install "INSTALL.md"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/fz version")
  end
end
