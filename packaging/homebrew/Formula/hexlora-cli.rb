class HexloraCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"
  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v1.3.2/hexlora-cli-1.3.2-aarch64-apple-darwin.tar.gz"
  sha256 "e060793c74021f3a4faf48c0f95c2bcb4e04c36de2c67125a6b5ddfe2935d130"
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
