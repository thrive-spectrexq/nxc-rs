class NxcRs < Formula
  desc "NetExec-RS - High-performance offensive network orchestration framework"
  homepage "https://github.com/thrive-spectrexq/nxc-rs"
  version "0.4.0"
  
  if OS.mac?
    url "https://github.com/thrive-spectrexq/nxc-rs/releases/download/v0.4.0/nxc-macos-amd64"
    sha256 "REPLACE_WITH_SHA256"
  elsif OS.linux?
    url "https://github.com/thrive-spectrexq/nxc-rs/releases/download/v0.4.0/nxc-linux-amd64"
    sha256 "REPLACE_WITH_SHA256"
  end

  def install
    if OS.mac?
      bin.install "nxc-macos-amd64" => "nxc"
    elsif OS.linux?
      bin.install "nxc-linux-amd64" => "nxc"
    end
  end

  test do
    system "#{bin}/nxc", "--help"
  end
end
