class HexloraCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://github.com/everettjf/hexlora"
  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v1.1.21/hexlora-cli-1.1.21-aarch64-apple-darwin.tar.gz"
  sha256 "d6b87b1d575923b8d79e7d5b8846b01a8f1a34a10c5a4cff6e3811c3580fbee3"
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
