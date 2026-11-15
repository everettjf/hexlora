class HexloraCli < Formula
  desc "Static application, package, and binary inspection workbench"
  homepage "https://atomsprout.com/hexlora/"
  url "https://github.com/everettjf/homebrew-tap/releases/download/hexlora-v1.2.0/hexlora-cli-1.2.0-aarch64-apple-darwin.tar.gz"
  sha256 "6e8e5732afb2f42b304823cc9b07c6e753d3f3bce5028d41fde82472a4299135"
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
