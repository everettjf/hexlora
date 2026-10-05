class HexloraCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/hexlora"
  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v1.1.17/hexlora-cli-1.1.17-aarch64-apple-darwin.tar.gz"
  sha256 "579cfdf98c054547a5f27679ce0113c923e59ebb97cdbc56b58be464728ef91b"
  license "Apache-2.0"

  depends_on arch: :arm64

  def install
    bin.install "hexlora-cli"
  end

  test do
    (testpath/"fixture.json").write('{"hexlora":true}')
    output = shell_output("#{bin}/hexlora-cli inspect #{testpath}/fixture.json --json")
    report = JSON.parse(output)
    assert_equal 1, report.fetch("schema_version")
    assert_equal false, report.dig("run", "partial")
  end
end
