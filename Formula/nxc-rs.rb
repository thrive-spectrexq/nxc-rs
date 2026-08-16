class NxcRs < Formula
  desc "NetExec-RS - High-performance offensive network orchestration framework"
  homepage "https://github.com/thrive-spectrexq/nxc-rs"
  version "0.4.5"
  
  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/thrive-spectrexq/nxc-rs/releases/download/v0.4.5/nxc-macos-arm64"
      sha256 "REPLACE_WITH_SHA256"
    else
      url "https://github.com/thrive-spectrexq/nxc-rs/releases/download/v0.4.5/nxc-macos-amd64"
      sha256 "REPLACE_WITH_SHA256"
    end
  elsif OS.linux?
    if Hardware::CPU.arm?
      url "https://github.com/thrive-spectrexq/nxc-rs/releases/download/v0.4.5/nxc-linux-arm64"
      sha256 "REPLACE_WITH_SHA256"
    else
      url "https://github.com/thrive-spectrexq/nxc-rs/releases/download/v0.4.5/nxc-linux-amd64"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  def install
    if OS.mac?
      if Hardware::CPU.arm?
        bin.install "nxc-macos-arm64" => "nxc"
      else
        bin.install "nxc-macos-amd64" => "nxc"
      end
    elsif OS.linux?
      if Hardware::CPU.arm?
        bin.install "nxc-linux-arm64" => "nxc"
      else
        bin.install "nxc-linux-amd64" => "nxc"
      end
    end
  end

  test do
    system "#{bin}/nxc", "--help"
  end
end
