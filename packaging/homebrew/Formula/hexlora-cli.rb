class HexloraCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"
  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v1.3.1/hexlora-cli-1.3.1-aarch64-apple-darwin.tar.gz"
  sha256 "9b99d6f322f966c1f2f93019a9377dbeb1b659fb2f5c0189332ad8db9a8b9822"
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
